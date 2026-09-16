rule TTP_XOR_MULT_DOSStub_0187 {
  strings:
    $key_0187 = { 55 ef [2] 21 f7 [2] 66 f5 [2] 21 e4 [2] 6f e8 [2] 63 e2 [2] 74 e9 [2] 6f a7 [2] 52 }

  condition:
    any of them
}