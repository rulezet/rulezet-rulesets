rule TTP_XOR_MULT_DOSStub_1fcf {
  strings:
    $key_1fcf = { 4b a7 [2] 3f bf [2] 78 bd [2] 3f ac [2] 71 a0 [2] 7d aa [2] 6a a1 [2] 71 ef [2] 4c }

  condition:
    any of them
}