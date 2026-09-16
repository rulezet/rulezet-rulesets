rule TTP_XOR_MULT_DOSStub_2fc6 {
  strings:
    $key_2fc6 = { 7b ae [2] 0f b6 [2] 48 b4 [2] 0f a5 [2] 41 a9 [2] 4d a3 [2] 5a a8 [2] 41 e6 [2] 7c }

  condition:
    any of them
}