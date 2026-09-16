rule TTP_XOR_MULT_DOSStub_07b7 {
  strings:
    $key_07b7 = { 53 df [2] 27 c7 [2] 60 c5 [2] 27 d4 [2] 69 d8 [2] 65 d2 [2] 72 d9 [2] 69 97 [2] 54 }

  condition:
    any of them
}