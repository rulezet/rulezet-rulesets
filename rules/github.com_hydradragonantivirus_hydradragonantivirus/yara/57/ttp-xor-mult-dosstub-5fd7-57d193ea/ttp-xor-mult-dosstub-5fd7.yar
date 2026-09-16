rule TTP_XOR_MULT_DOSStub_5fd7 {
  strings:
    $key_5fd7 = { 0b bf [2] 7f a7 [2] 38 a5 [2] 7f b4 [2] 31 b8 [2] 3d b2 [2] 2a b9 [2] 31 f7 [2] 0c }

  condition:
    any of them
}