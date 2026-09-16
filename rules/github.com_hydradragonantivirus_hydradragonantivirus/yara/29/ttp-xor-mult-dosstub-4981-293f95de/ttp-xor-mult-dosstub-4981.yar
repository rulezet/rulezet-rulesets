rule TTP_XOR_MULT_DOSStub_4981 {
  strings:
    $key_4981 = { 1d e9 [2] 69 f1 [2] 2e f3 [2] 69 e2 [2] 27 ee [2] 2b e4 [2] 3c ef [2] 27 a1 [2] 1a }

  condition:
    any of them
}