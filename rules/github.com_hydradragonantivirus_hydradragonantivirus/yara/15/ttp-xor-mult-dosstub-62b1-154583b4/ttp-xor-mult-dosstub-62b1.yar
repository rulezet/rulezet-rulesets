rule TTP_XOR_MULT_DOSStub_62b1 {
  strings:
    $key_62b1 = { 36 d9 [2] 42 c1 [2] 05 c3 [2] 42 d2 [2] 0c de [2] 00 d4 [2] 17 df [2] 0c 91 [2] 31 }

  condition:
    any of them
}