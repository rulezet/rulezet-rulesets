rule TTP_XOR_MULT_DOSStub_1077 {
  strings:
    $key_1077 = { 44 1f [2] 30 07 [2] 77 05 [2] 30 14 [2] 7e 18 [2] 72 12 [2] 65 19 [2] 7e 57 [2] 43 }

  condition:
    any of them
}