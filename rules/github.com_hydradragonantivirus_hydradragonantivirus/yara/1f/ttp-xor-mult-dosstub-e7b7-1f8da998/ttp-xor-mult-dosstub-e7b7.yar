rule TTP_XOR_MULT_DOSStub_e7b7 {
  strings:
    $key_e7b7 = { b3 df [2] c7 c7 [2] 80 c5 [2] c7 d4 [2] 89 d8 [2] 85 d2 [2] 92 d9 [2] 89 97 [2] b4 }

  condition:
    any of them
}