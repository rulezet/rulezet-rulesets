rule TTP_XOR_MULT_DOSStub_1571 {
  strings:
    $key_1571 = { 41 19 [2] 35 01 [2] 72 03 [2] 35 12 [2] 7b 1e [2] 77 14 [2] 60 1f [2] 7b 51 [2] 46 }

  condition:
    any of them
}