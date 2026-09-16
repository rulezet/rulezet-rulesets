rule TTP_XOR_MULT_DOSStub_7381 {
  strings:
    $key_7381 = { 27 e9 [2] 53 f1 [2] 14 f3 [2] 53 e2 [2] 1d ee [2] 11 e4 [2] 06 ef [2] 1d a1 [2] 20 }

  condition:
    any of them
}