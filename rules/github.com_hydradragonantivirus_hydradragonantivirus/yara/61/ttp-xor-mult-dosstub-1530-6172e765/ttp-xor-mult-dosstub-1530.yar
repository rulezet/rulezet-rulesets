rule TTP_XOR_MULT_DOSStub_1530 {
  strings:
    $key_1530 = { 41 58 [2] 35 40 [2] 72 42 [2] 35 53 [2] 7b 5f [2] 77 55 [2] 60 5e [2] 7b 10 [2] 46 }

  condition:
    any of them
}