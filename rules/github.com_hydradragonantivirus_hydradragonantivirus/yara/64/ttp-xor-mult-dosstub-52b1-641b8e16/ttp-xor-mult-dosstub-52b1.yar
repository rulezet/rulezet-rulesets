rule TTP_XOR_MULT_DOSStub_52b1 {
  strings:
    $key_52b1 = { 06 d9 [2] 72 c1 [2] 35 c3 [2] 72 d2 [2] 3c de [2] 30 d4 [2] 27 df [2] 3c 91 [2] 01 }

  condition:
    any of them
}