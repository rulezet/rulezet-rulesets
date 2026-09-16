rule TTP_XOR_MULT_DOSStub_a55d {
  strings:
    $key_a55d = { f1 35 [2] 85 2d [2] c2 2f [2] 85 3e [2] cb 32 [2] c7 38 [2] d0 33 [2] cb 7d [2] f6 }

  condition:
    any of them
}