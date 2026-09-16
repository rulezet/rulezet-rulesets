rule TTP_XOR_MULT_DOSStub_1565 {
  strings:
    $key_1565 = { 41 0d [2] 35 15 [2] 72 17 [2] 35 06 [2] 7b 0a [2] 77 00 [2] 60 0b [2] 7b 45 [2] 46 }

  condition:
    any of them
}