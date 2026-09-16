rule TTP_XOR_MULT_DOSStub_1720 {
  strings:
    $key_1720 = { 43 48 [2] 37 50 [2] 70 52 [2] 37 43 [2] 79 4f [2] 75 45 [2] 62 4e [2] 79 00 [2] 44 }

  condition:
    any of them
}