rule TTP_XOR_MULT_DOSStub_55b1 {
  strings:
    $key_55b1 = { 01 d9 [2] 75 c1 [2] 32 c3 [2] 75 d2 [2] 3b de [2] 37 d4 [2] 20 df [2] 3b 91 [2] 06 }

  condition:
    any of them
}