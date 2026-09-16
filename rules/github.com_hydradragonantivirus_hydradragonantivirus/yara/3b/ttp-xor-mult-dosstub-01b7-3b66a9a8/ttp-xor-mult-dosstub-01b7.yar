rule TTP_XOR_MULT_DOSStub_01b7 {
  strings:
    $key_01b7 = { 55 df [2] 21 c7 [2] 66 c5 [2] 21 d4 [2] 6f d8 [2] 63 d2 [2] 74 d9 [2] 6f 97 [2] 52 }

  condition:
    any of them
}