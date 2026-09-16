rule TTP_XOR_MULT_DOSStub_5536 {
  strings:
    $key_5536 = { 01 5e [2] 75 46 [2] 32 44 [2] 75 55 [2] 3b 59 [2] 37 53 [2] 20 58 [2] 3b 16 [2] 06 }

  condition:
    any of them
}