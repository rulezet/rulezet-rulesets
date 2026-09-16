rule TTP_XOR_MULT_DOSStub_e142 {
  strings:
    $key_e142 = { b5 2a [2] c1 32 [2] 86 30 [2] c1 21 [2] 8f 2d [2] 83 27 [2] 94 2c [2] 8f 62 [2] b2 }

  condition:
    any of them
}