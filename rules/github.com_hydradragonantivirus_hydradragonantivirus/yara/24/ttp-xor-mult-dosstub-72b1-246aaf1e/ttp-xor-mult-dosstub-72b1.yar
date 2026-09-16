rule TTP_XOR_MULT_DOSStub_72b1 {
  strings:
    $key_72b1 = { 26 d9 [2] 52 c1 [2] 15 c3 [2] 52 d2 [2] 1c de [2] 10 d4 [2] 07 df [2] 1c 91 [2] 21 }

  condition:
    any of them
}