rule TTP_XOR_MULT_DOSStub_2381 {
  strings:
    $key_2381 = { 77 e9 [2] 03 f1 [2] 44 f3 [2] 03 e2 [2] 4d ee [2] 41 e4 [2] 56 ef [2] 4d a1 [2] 70 }

  condition:
    any of them
}