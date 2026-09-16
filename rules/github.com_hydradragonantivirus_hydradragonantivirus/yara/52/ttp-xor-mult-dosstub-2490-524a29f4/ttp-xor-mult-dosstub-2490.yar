rule TTP_XOR_MULT_DOSStub_2490 {
  strings:
    $key_2490 = { 70 f8 [2] 04 e0 [2] 43 e2 [2] 04 f3 [2] 4a ff [2] 46 f5 [2] 51 fe [2] 4a b0 [2] 77 }

  condition:
    any of them
}