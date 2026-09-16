rule TTP_XOR_MULT_DOSStub_6290 {
  strings:
    $key_6290 = { 36 f8 [2] 42 e0 [2] 05 e2 [2] 42 f3 [2] 0c ff [2] 00 f5 [2] 17 fe [2] 0c b0 [2] 31 }

  condition:
    any of them
}