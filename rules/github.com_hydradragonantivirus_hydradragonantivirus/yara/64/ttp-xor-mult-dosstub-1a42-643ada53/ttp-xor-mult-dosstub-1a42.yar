rule TTP_XOR_MULT_DOSStub_1a42 {
  strings:
    $key_1a42 = { 4e 2a [2] 3a 32 [2] 7d 30 [2] 3a 21 [2] 74 2d [2] 78 27 [2] 6f 2c [2] 74 62 [2] 49 }

  condition:
    any of them
}