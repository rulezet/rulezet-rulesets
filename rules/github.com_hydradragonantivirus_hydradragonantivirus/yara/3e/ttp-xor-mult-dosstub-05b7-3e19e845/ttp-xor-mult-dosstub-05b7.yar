rule TTP_XOR_MULT_DOSStub_05b7 {
  strings:
    $key_05b7 = { 51 df [2] 25 c7 [2] 62 c5 [2] 25 d4 [2] 6b d8 [2] 67 d2 [2] 70 d9 [2] 6b 97 [2] 56 }

  condition:
    any of them
}