rule TTP_XOR_MULT_DOSStub_61b7 {
  strings:
    $key_61b7 = { 35 df [2] 41 c7 [2] 06 c5 [2] 41 d4 [2] 0f d8 [2] 03 d2 [2] 14 d9 [2] 0f 97 [2] 32 }

  condition:
    any of them
}