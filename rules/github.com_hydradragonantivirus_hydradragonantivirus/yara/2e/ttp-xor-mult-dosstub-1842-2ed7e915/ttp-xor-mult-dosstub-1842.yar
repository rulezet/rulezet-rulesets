rule TTP_XOR_MULT_DOSStub_1842 {
  strings:
    $key_1842 = { 4c 2a [2] 38 32 [2] 7f 30 [2] 38 21 [2] 76 2d [2] 7a 27 [2] 6d 2c [2] 76 62 [2] 4b }

  condition:
    any of them
}