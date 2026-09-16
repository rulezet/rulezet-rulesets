rule TTP_XOR_MULT_DOSStub_421a {
  strings:
    $key_421a = { 16 72 [2] 62 6a [2] 25 68 [2] 62 79 [2] 2c 75 [2] 20 7f [2] 37 74 [2] 2c 3a [2] 11 }

  condition:
    any of them
}