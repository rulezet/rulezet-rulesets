rule TTP_XOR_MULT_DOSStub_bbcf {
  strings:
    $key_bbcf = { ef a7 [2] 9b bf [2] dc bd [2] 9b ac [2] d5 a0 [2] d9 aa [2] ce a1 [2] d5 ef [2] e8 }

  condition:
    any of them
}