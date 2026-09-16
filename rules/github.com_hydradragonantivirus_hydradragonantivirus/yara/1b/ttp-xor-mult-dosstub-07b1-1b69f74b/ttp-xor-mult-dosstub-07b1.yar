rule TTP_XOR_MULT_DOSStub_07b1 {
  strings:
    $key_07b1 = { 53 d9 [2] 27 c1 [2] 60 c3 [2] 27 d2 [2] 69 de [2] 65 d4 [2] 72 df [2] 69 91 [2] 54 }

  condition:
    any of them
}