rule TTP_XOR_MULT_DOSStub_0381 {
  strings:
    $key_0381 = { 57 e9 [2] 23 f1 [2] 64 f3 [2] 23 e2 [2] 6d ee [2] 61 e4 [2] 76 ef [2] 6d a1 [2] 50 }

  condition:
    any of them
}