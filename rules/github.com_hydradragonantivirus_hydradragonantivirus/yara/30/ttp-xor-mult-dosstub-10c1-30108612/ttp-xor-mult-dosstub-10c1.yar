rule TTP_XOR_MULT_DOSStub_10c1 {
  strings:
    $key_10c1 = { 44 a9 [2] 30 b1 [2] 77 b3 [2] 30 a2 [2] 7e ae [2] 72 a4 [2] 65 af [2] 7e e1 [2] 43 }

  condition:
    any of them
}