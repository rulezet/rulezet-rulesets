rule TTP_XOR_MULT_DOSStub_48c0 {
  strings:
    $key_48c0 = { 1c a8 [2] 68 b0 [2] 2f b2 [2] 68 a3 [2] 26 af [2] 2a a5 [2] 3d ae [2] 26 e0 [2] 1b }

  condition:
    any of them
}