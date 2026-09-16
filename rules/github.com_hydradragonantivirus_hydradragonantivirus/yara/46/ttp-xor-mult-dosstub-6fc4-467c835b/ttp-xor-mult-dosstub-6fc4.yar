rule TTP_XOR_MULT_DOSStub_6fc4 {
  strings:
    $key_6fc4 = { 3b ac [2] 4f b4 [2] 08 b6 [2] 4f a7 [2] 01 ab [2] 0d a1 [2] 1a aa [2] 01 e4 [2] 3c }

  condition:
    any of them
}