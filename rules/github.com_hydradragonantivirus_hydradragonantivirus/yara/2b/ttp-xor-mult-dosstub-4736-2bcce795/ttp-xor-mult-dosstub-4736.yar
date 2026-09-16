rule TTP_XOR_MULT_DOSStub_4736 {
  strings:
    $key_4736 = { 13 5e [2] 67 46 [2] 20 44 [2] 67 55 [2] 29 59 [2] 25 53 [2] 32 58 [2] 29 16 [2] 14 }

  condition:
    any of them
}