rule TTP_XOR_MULT_DOSStub_3287 {
  strings:
    $key_3287 = { 66 ef [2] 12 f7 [2] 55 f5 [2] 12 e4 [2] 5c e8 [2] 50 e2 [2] 47 e9 [2] 5c a7 [2] 61 }

  condition:
    any of them
}