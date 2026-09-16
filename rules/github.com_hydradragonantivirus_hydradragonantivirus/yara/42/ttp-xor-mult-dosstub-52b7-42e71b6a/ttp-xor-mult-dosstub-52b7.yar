rule TTP_XOR_MULT_DOSStub_52b7 {
  strings:
    $key_52b7 = { 06 df [2] 72 c7 [2] 35 c5 [2] 72 d4 [2] 3c d8 [2] 30 d2 [2] 27 d9 [2] 3c 97 [2] 01 }

  condition:
    any of them
}