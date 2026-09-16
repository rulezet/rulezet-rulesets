rule TTP_XOR_MULT_DOSStub_3987 {
  strings:
    $key_3987 = { 6d ef [2] 19 f7 [2] 5e f5 [2] 19 e4 [2] 57 e8 [2] 5b e2 [2] 4c e9 [2] 57 a7 [2] 6a }

  condition:
    any of them
}