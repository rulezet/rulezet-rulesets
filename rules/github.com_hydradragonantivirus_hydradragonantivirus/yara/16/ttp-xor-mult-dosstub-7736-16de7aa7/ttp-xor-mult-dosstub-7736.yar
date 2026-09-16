rule TTP_XOR_MULT_DOSStub_7736 {
  strings:
    $key_7736 = { 23 5e [2] 57 46 [2] 10 44 [2] 57 55 [2] 19 59 [2] 15 53 [2] 02 58 [2] 19 16 [2] 24 }

  condition:
    any of them
}