rule TTP_XOR_MULT_DOSStub_1081 {
  strings:
    $key_1081 = { 44 e9 [2] 30 f1 [2] 77 f3 [2] 30 e2 [2] 7e ee [2] 72 e4 [2] 65 ef [2] 7e a1 [2] 43 }

  condition:
    any of them
}