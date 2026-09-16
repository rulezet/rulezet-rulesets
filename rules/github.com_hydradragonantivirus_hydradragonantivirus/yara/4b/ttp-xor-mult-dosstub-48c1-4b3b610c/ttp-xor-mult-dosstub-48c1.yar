rule TTP_XOR_MULT_DOSStub_48c1 {
  strings:
    $key_48c1 = { 1c a9 [2] 68 b1 [2] 2f b3 [2] 68 a2 [2] 26 ae [2] 2a a4 [2] 3d af [2] 26 e1 [2] 1b }

  condition:
    any of them
}