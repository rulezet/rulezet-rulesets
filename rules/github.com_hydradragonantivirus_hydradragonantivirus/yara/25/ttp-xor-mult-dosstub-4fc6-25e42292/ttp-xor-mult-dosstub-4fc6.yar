rule TTP_XOR_MULT_DOSStub_4fc6 {
  strings:
    $key_4fc6 = { 1b ae [2] 6f b6 [2] 28 b4 [2] 6f a5 [2] 21 a9 [2] 2d a3 [2] 3a a8 [2] 21 e6 [2] 1c }

  condition:
    any of them
}