rule TTP_XOR_MULT_DOSStub_25b1 {
  strings:
    $key_25b1 = { 71 d9 [2] 05 c1 [2] 42 c3 [2] 05 d2 [2] 4b de [2] 47 d4 [2] 50 df [2] 4b 91 [2] 76 }

  condition:
    any of them
}