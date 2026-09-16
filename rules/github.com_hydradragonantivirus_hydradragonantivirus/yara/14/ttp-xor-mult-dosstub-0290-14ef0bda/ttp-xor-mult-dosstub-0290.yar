rule TTP_XOR_MULT_DOSStub_0290 {
  strings:
    $key_0290 = { 56 f8 [2] 22 e0 [2] 65 e2 [2] 22 f3 [2] 6c ff [2] 60 f5 [2] 77 fe [2] 6c b0 [2] 51 }

  condition:
    any of them
}