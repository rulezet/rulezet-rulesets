rule TTP_XOR_MULT_DOSStub_fdcf {
  strings:
    $key_fdcf = { a9 a7 [2] dd bf [2] 9a bd [2] dd ac [2] 93 a0 [2] 9f aa [2] 88 a1 [2] 93 ef [2] ae }

  condition:
    any of them
}