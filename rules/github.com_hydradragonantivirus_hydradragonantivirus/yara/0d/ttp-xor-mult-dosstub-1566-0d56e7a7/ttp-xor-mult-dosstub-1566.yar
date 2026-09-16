rule TTP_XOR_MULT_DOSStub_1566 {
  strings:
    $key_1566 = { 41 0e [2] 35 16 [2] 72 14 [2] 35 05 [2] 7b 09 [2] 77 03 [2] 60 08 [2] 7b 46 [2] 46 }

  condition:
    any of them
}