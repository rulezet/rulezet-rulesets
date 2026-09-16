rule TTP_XOR_MULT_DOSStub_65b1 {
  strings:
    $key_65b1 = { 31 d9 [2] 45 c1 [2] 02 c3 [2] 45 d2 [2] 0b de [2] 07 d4 [2] 10 df [2] 0b 91 [2] 36 }

  condition:
    any of them
}