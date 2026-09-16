rule TTP_XOR_MULT_DOSStub_3981 {
  strings:
    $key_3981 = { 6d e9 [2] 19 f1 [2] 5e f3 [2] 19 e2 [2] 57 ee [2] 5b e4 [2] 4c ef [2] 57 a1 [2] 6a }

  condition:
    any of them
}