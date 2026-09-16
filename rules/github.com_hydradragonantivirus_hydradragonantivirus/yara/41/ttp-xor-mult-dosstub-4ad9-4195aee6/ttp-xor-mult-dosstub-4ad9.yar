rule TTP_XOR_MULT_DOSStub_4ad9 {
  strings:
    $key_4ad9 = { 1e b1 [2] 6a a9 [2] 2d ab [2] 6a ba [2] 24 b6 [2] 28 bc [2] 3f b7 [2] 24 f9 [2] 19 }

  condition:
    any of them
}