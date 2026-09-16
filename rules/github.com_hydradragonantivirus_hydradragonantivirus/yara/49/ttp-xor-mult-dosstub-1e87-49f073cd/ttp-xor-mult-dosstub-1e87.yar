rule TTP_XOR_MULT_DOSStub_1e87 {
  strings:
    $key_1e87 = { 4a ef [2] 3e f7 [2] 79 f5 [2] 3e e4 [2] 70 e8 [2] 7c e2 [2] 6b e9 [2] 70 a7 [2] 4d }

  condition:
    any of them
}