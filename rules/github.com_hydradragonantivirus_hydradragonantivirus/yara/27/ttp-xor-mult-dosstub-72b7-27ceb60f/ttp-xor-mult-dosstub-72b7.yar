rule TTP_XOR_MULT_DOSStub_72b7 {
  strings:
    $key_72b7 = { 26 df [2] 52 c7 [2] 15 c5 [2] 52 d4 [2] 1c d8 [2] 10 d2 [2] 07 d9 [2] 1c 97 [2] 21 }

  condition:
    any of them
}