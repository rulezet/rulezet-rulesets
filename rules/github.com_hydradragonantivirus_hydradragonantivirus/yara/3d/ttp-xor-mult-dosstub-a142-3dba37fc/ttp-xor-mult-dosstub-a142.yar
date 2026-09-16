rule TTP_XOR_MULT_DOSStub_a142 {
  strings:
    $key_a142 = { f5 2a [2] 81 32 [2] c6 30 [2] 81 21 [2] cf 2d [2] c3 27 [2] d4 2c [2] cf 62 [2] f2 }

  condition:
    any of them
}