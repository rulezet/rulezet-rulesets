rule TTP_XOR_MULT_DOSStub_06b7 {
  strings:
    $key_06b7 = { 52 df [2] 26 c7 [2] 61 c5 [2] 26 d4 [2] 68 d8 [2] 64 d2 [2] 73 d9 [2] 68 97 [2] 55 }

  condition:
    any of them
}