rule TTP_XOR_MULT_DOSStub_76b1 {
  strings:
    $key_76b1 = { 22 d9 [2] 56 c1 [2] 11 c3 [2] 56 d2 [2] 18 de [2] 14 d4 [2] 03 df [2] 18 91 [2] 25 }

  condition:
    any of them
}