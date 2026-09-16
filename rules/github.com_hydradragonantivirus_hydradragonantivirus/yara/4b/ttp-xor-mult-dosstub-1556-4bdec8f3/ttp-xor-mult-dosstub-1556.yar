rule TTP_XOR_MULT_DOSStub_1556 {
  strings:
    $key_1556 = { 41 3e [2] 35 26 [2] 72 24 [2] 35 35 [2] 7b 39 [2] 77 33 [2] 60 38 [2] 7b 76 [2] 46 }

  condition:
    any of them
}