rule TTP_XOR_MULT_DOSStub_e290 {
  strings:
    $key_e290 = { b6 f8 [2] c2 e0 [2] 85 e2 [2] c2 f3 [2] 8c ff [2] 80 f5 [2] 97 fe [2] 8c b0 [2] b1 }

  condition:
    any of them
}