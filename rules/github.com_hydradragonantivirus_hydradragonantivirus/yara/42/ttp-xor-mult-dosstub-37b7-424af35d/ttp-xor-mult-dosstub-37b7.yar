rule TTP_XOR_MULT_DOSStub_37b7 {
  strings:
    $key_37b7 = { 63 df [2] 17 c7 [2] 50 c5 [2] 17 d4 [2] 59 d8 [2] 55 d2 [2] 42 d9 [2] 59 97 [2] 64 }

  condition:
    any of them
}