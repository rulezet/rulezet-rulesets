rule TTP_XOR_MULT_DOSStub_1560 {
  strings:
    $key_1560 = { 41 08 [2] 35 10 [2] 72 12 [2] 35 03 [2] 7b 0f [2] 77 05 [2] 60 0e [2] 7b 40 [2] 46 }

  condition:
    any of them
}