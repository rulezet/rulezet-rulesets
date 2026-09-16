rule TTP_XOR_MULT_DOSStub_1577 {
  strings:
    $key_1577 = { 41 1f [2] 35 07 [2] 72 05 [2] 35 14 [2] 7b 18 [2] 77 12 [2] 60 19 [2] 7b 57 [2] 46 }

  condition:
    any of them
}