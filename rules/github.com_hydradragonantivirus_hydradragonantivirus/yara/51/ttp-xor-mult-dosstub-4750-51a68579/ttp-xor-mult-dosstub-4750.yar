rule TTP_XOR_MULT_DOSStub_4750 {
  strings:
    $key_4750 = { 13 38 [2] 67 20 [2] 20 22 [2] 67 33 [2] 29 3f [2] 25 35 [2] 32 3e [2] 29 70 [2] 14 }

  condition:
    any of them
}