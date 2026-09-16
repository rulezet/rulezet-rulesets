rule TTP_XOR_MULT_DOSStub_2187 {
  strings:
    $key_2187 = { 75 ef [2] 01 f7 [2] 46 f5 [2] 01 e4 [2] 4f e8 [2] 43 e2 [2] 54 e9 [2] 4f a7 [2] 72 }

  condition:
    any of them
}