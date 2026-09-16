rule TTP_XOR_MULT_DOSStub_5427 {
  strings:
    $key_5427 = { 00 4f [2] 74 57 [2] 33 55 [2] 74 44 [2] 3a 48 [2] 36 42 [2] 21 49 [2] 3a 07 [2] 07 }

  condition:
    any of them
}