rule TTP_XOR_MULT_DOSStub_1526 {
  strings:
    $key_1526 = { 41 4e [2] 35 56 [2] 72 54 [2] 35 45 [2] 7b 49 [2] 77 43 [2] 60 48 [2] 7b 06 [2] 46 }

  condition:
    any of them
}