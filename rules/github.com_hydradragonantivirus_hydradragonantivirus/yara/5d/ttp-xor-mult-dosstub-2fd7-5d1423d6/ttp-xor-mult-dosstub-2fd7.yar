rule TTP_XOR_MULT_DOSStub_2fd7 {
  strings:
    $key_2fd7 = { 7b bf [2] 0f a7 [2] 48 a5 [2] 0f b4 [2] 41 b8 [2] 4d b2 [2] 5a b9 [2] 41 f7 [2] 7c }

  condition:
    any of them
}