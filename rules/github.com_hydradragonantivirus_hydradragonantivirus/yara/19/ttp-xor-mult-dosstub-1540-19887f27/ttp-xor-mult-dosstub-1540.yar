rule TTP_XOR_MULT_DOSStub_1540 {
  strings:
    $key_1540 = { 41 28 [2] 35 30 [2] 72 32 [2] 35 23 [2] 7b 2f [2] 77 25 [2] 60 2e [2] 7b 60 [2] 46 }

  condition:
    any of them
}