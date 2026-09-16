rule TTP_XOR_MULT_DOSStub_3781 {
  strings:
    $key_3781 = { 63 e9 [2] 17 f1 [2] 50 f3 [2] 17 e2 [2] 59 ee [2] 55 e4 [2] 42 ef [2] 59 a1 [2] 64 }

  condition:
    any of them
}