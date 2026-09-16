rule TTP_XOR_MULT_DOSStub_02b1 {
  strings:
    $key_02b1 = { 56 d9 [2] 22 c1 [2] 65 c3 [2] 22 d2 [2] 6c de [2] 60 d4 [2] 77 df [2] 6c 91 [2] 51 }

  condition:
    any of them
}