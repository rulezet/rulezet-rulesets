rule TTP_XOR_MULT_DOSStub_7448 {
  strings:
    $key_7448 = { 20 20 [2] 54 38 [2] 13 3a [2] 54 2b [2] 1a 27 [2] 16 2d [2] 01 26 [2] 1a 68 [2] 27 }

  condition:
    any of them
}