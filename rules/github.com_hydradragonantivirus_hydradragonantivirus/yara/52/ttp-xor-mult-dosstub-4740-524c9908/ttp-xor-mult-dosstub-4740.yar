rule TTP_XOR_MULT_DOSStub_4740 {
  strings:
    $key_4740 = { 13 28 [2] 67 30 [2] 20 32 [2] 67 23 [2] 29 2f [2] 25 25 [2] 32 2e [2] 29 60 [2] 14 }

  condition:
    any of them
}