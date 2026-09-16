rule TTP_XOR_MULT_DOSStub_a396 {
  strings:
    $key_a396 = { f7 fe [2] 83 e6 [2] c4 e4 [2] 83 f5 [2] cd f9 [2] c1 f3 [2] d6 f8 [2] cd b6 [2] f0 }

  condition:
    any of them
}