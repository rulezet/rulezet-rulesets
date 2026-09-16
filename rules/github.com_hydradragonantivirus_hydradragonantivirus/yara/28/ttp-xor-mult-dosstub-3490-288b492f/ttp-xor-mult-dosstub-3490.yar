rule TTP_XOR_MULT_DOSStub_3490 {
  strings:
    $key_3490 = { 60 f8 [2] 14 e0 [2] 53 e2 [2] 14 f3 [2] 5a ff [2] 56 f5 [2] 41 fe [2] 5a b0 [2] 67 }

  condition:
    any of them
}