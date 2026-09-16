rule TTP_XOR_MULT_DOSStub_1590 {
  strings:
    $key_1590 = { 41 f8 [2] 35 e0 [2] 72 e2 [2] 35 f3 [2] 7b ff [2] 77 f5 [2] 60 fe [2] 7b b0 [2] 46 }

  condition:
    any of them
}