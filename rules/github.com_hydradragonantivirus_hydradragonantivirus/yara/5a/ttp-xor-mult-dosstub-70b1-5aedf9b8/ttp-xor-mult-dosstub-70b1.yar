rule TTP_XOR_MULT_DOSStub_70b1 {
  strings:
    $key_70b1 = { 24 d9 [2] 50 c1 [2] 17 c3 [2] 50 d2 [2] 1e de [2] 12 d4 [2] 05 df [2] 1e 91 [2] 23 }

  condition:
    any of them
}