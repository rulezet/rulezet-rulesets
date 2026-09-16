rule TTP_XOR_MULT_DOSStub_65b7 {
  strings:
    $key_65b7 = { 31 df [2] 45 c7 [2] 02 c5 [2] 45 d4 [2] 0b d8 [2] 07 d2 [2] 10 d9 [2] 0b 97 [2] 36 }

  condition:
    any of them
}