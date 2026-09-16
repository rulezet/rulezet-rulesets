rule TTP_XOR_MULT_DOSStub_4fc4 {
  strings:
    $key_4fc4 = { 1b ac [2] 6f b4 [2] 28 b6 [2] 6f a7 [2] 21 ab [2] 2d a1 [2] 3a aa [2] 21 e4 [2] 1c }

  condition:
    any of them
}