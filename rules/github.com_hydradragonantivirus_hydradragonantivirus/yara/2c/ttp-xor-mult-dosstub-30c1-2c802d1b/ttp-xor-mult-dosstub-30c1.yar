rule TTP_XOR_MULT_DOSStub_30c1 {
  strings:
    $key_30c1 = { 64 a9 [2] 10 b1 [2] 57 b3 [2] 10 a2 [2] 5e ae [2] 52 a4 [2] 45 af [2] 5e e1 [2] 63 }

  condition:
    any of them
}