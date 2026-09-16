rule TTP_XOR_MULT_DOSStub_76b7 {
  strings:
    $key_76b7 = { 22 df [2] 56 c7 [2] 11 c5 [2] 56 d4 [2] 18 d8 [2] 14 d2 [2] 03 d9 [2] 18 97 [2] 25 }

  condition:
    any of them
}