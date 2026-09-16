rule TTP_XOR_MULT_DOSStub_7fc7 {
  strings:
    $key_7fc7 = { 2b af [2] 5f b7 [2] 18 b5 [2] 5f a4 [2] 11 a8 [2] 1d a2 [2] 0a a9 [2] 11 e7 [2] 2c }

  condition:
    any of them
}