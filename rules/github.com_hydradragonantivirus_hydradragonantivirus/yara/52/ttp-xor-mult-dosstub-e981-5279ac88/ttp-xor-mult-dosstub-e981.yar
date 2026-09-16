rule TTP_XOR_MULT_DOSStub_e981 {
  strings:
    $key_e981 = { bd e9 [2] c9 f1 [2] 8e f3 [2] c9 e2 [2] 87 ee [2] 8b e4 [2] 9c ef [2] 87 a1 [2] ba }

  condition:
    any of them
}