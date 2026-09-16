rule TTP_XOR_MULT_DOSStub_1500 {
  strings:
    $key_1500 = { 41 68 [2] 35 70 [2] 72 72 [2] 35 63 [2] 7b 6f [2] 77 65 [2] 60 6e [2] 7b 20 [2] 46 }

  condition:
    any of them
}