rule TTP_XOR_MULT_DOSStub_2fc7 {
  strings:
    $key_2fc7 = { 7b af [2] 0f b7 [2] 48 b5 [2] 0f a4 [2] 41 a8 [2] 4d a2 [2] 5a a9 [2] 41 e7 [2] 7c }

  condition:
    any of them
}