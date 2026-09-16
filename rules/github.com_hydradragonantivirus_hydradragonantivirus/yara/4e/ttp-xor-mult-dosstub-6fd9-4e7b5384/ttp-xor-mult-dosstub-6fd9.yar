rule TTP_XOR_MULT_DOSStub_6fd9 {
  strings:
    $key_6fd9 = { 3b b1 [2] 4f a9 [2] 08 ab [2] 4f ba [2] 01 b6 [2] 0d bc [2] 1a b7 [2] 01 f9 [2] 3c }

  condition:
    any of them
}