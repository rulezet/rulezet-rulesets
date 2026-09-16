rule TTP_XOR_MULT_DOSStub_1448 {
  strings:
    $key_1448 = { 40 20 [2] 34 38 [2] 73 3a [2] 34 2b [2] 7a 27 [2] 76 2d [2] 61 26 [2] 7a 68 [2] 47 }

  condition:
    any of them
}