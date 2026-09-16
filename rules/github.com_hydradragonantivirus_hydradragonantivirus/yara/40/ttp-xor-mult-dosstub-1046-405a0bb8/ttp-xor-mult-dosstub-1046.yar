rule TTP_XOR_MULT_DOSStub_1046 {
  strings:
    $key_1046 = { 44 2e [2] 30 36 [2] 77 34 [2] 30 25 [2] 7e 29 [2] 72 23 [2] 65 28 [2] 7e 66 [2] 43 }

  condition:
    any of them
}