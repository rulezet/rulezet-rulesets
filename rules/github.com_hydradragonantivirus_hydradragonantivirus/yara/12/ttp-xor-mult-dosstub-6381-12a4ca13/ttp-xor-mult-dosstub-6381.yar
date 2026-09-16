rule TTP_XOR_MULT_DOSStub_6381 {
  strings:
    $key_6381 = { 37 e9 [2] 43 f1 [2] 04 f3 [2] 43 e2 [2] 0d ee [2] 01 e4 [2] 16 ef [2] 0d a1 [2] 30 }

  condition:
    any of them
}