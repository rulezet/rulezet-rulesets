rule TTP_XOR_MULT_DOSStub_7187 {
  strings:
    $key_7187 = { 25 ef [2] 51 f7 [2] 16 f5 [2] 51 e4 [2] 1f e8 [2] 13 e2 [2] 04 e9 [2] 1f a7 [2] 22 }

  condition:
    any of them
}