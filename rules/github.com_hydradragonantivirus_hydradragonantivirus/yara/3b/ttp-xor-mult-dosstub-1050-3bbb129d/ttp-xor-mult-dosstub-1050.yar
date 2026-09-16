rule TTP_XOR_MULT_DOSStub_1050 {
  strings:
    $key_1050 = { 44 38 [2] 30 20 [2] 77 22 [2] 30 33 [2] 7e 3f [2] 72 35 [2] 65 3e [2] 7e 70 [2] 43 }

  condition:
    any of them
}