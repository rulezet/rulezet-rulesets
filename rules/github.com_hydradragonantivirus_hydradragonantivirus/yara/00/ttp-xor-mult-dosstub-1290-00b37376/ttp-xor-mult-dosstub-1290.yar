rule TTP_XOR_MULT_DOSStub_1290 {
  strings:
    $key_1290 = { 46 f8 [2] 32 e0 [2] 75 e2 [2] 32 f3 [2] 7c ff [2] 70 f5 [2] 67 fe [2] 7c b0 [2] 41 }

  condition:
    any of them
}