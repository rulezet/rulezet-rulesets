rule TTP_XOR_MULT_DOSStub_e987 {
  strings:
    $key_e987 = { bd ef [2] c9 f7 [2] 8e f5 [2] c9 e4 [2] 87 e8 [2] 8b e2 [2] 9c e9 [2] 87 a7 [2] ba }

  condition:
    any of them
}