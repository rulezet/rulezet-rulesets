rule TTP_XOR_MULT_DOSStub_6490 {
  strings:
    $key_6490 = { 30 f8 [2] 44 e0 [2] 03 e2 [2] 44 f3 [2] 0a ff [2] 06 f5 [2] 11 fe [2] 0a b0 [2] 37 }

  condition:
    any of them
}