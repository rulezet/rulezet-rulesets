rule TTP_XOR_MULT_DOSStub_7750 {
  strings:
    $key_7750 = { 23 38 [2] 57 20 [2] 10 22 [2] 57 33 [2] 19 3f [2] 15 35 [2] 02 3e [2] 19 70 [2] 24 }

  condition:
    any of them
}