rule TTP_XOR_MULT_DOSStub_e442 {
  strings:
    $key_e442 = { b0 2a [2] c4 32 [2] 83 30 [2] c4 21 [2] 8a 2d [2] 86 27 [2] 91 2c [2] 8a 62 [2] b7 }

  condition:
    any of them
}