rule TTP_XOR_MULT_DOSStub_4627 {
  strings:
    $key_4627 = { 12 4f [2] 66 57 [2] 21 55 [2] 66 44 [2] 28 48 [2] 24 42 [2] 33 49 [2] 28 07 [2] 15 }

  condition:
    any of them
}