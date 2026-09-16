rule TTP_XOR_MULT_DOSStub_5fc7 {
  strings:
    $key_5fc7 = { 0b af [2] 7f b7 [2] 38 b5 [2] 7f a4 [2] 31 a8 [2] 3d a2 [2] 2a a9 [2] 31 e7 [2] 0c }

  condition:
    any of them
}