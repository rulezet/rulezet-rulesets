rule TTP_XOR_MULT_DOSStub_a342 {
  strings:
    $key_a342 = { f7 2a [2] 83 32 [2] c4 30 [2] 83 21 [2] cd 2d [2] c1 27 [2] d6 2c [2] cd 62 [2] f0 }

  condition:
    any of them
}