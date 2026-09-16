rule TTP_XOR_MULT_DOSStub_4fc7 {
  strings:
    $key_4fc7 = { 1b af [2] 6f b7 [2] 28 b5 [2] 6f a4 [2] 21 a8 [2] 2d a2 [2] 3a a9 [2] 21 e7 [2] 1c }

  condition:
    any of them
}