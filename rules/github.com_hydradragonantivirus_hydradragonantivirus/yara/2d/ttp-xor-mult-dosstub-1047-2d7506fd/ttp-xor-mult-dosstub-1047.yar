rule TTP_XOR_MULT_DOSStub_1047 {
  strings:
    $key_1047 = { 44 2f [2] 30 37 [2] 77 35 [2] 30 24 [2] 7e 28 [2] 72 22 [2] 65 29 [2] 7e 67 [2] 43 }

  condition:
    any of them
}