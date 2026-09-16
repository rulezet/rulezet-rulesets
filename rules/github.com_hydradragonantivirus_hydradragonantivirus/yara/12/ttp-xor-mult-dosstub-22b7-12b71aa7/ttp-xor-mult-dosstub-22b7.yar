rule TTP_XOR_MULT_DOSStub_22b7 {
  strings:
    $key_22b7 = { 76 df [2] 02 c7 [2] 45 c5 [2] 02 d4 [2] 4c d8 [2] 40 d2 [2] 57 d9 [2] 4c 97 [2] 71 }

  condition:
    any of them
}