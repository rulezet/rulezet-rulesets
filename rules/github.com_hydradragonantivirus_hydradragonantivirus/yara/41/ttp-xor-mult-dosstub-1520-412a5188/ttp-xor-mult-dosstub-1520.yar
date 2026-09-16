rule TTP_XOR_MULT_DOSStub_1520 {
  strings:
    $key_1520 = { 41 48 [2] 35 50 [2] 72 52 [2] 35 43 [2] 7b 4f [2] 77 45 [2] 60 4e [2] 7b 00 [2] 46 }

  condition:
    any of them
}