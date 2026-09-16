rule TTP_XOR_MULT_DOSStub_47b1 {
  strings:
    $key_47b1 = { 13 d9 [2] 67 c1 [2] 20 c3 [2] 67 d2 [2] 29 de [2] 25 d4 [2] 32 df [2] 29 91 [2] 14 }

  condition:
    any of them
}