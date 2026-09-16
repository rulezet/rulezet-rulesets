rule TTP_XOR_MULT_DOSStub_3290 {
  strings:
    $key_3290 = { 66 f8 [2] 12 e0 [2] 55 e2 [2] 12 f3 [2] 5c ff [2] 50 f5 [2] 47 fe [2] 5c b0 [2] 61 }

  condition:
    any of them
}