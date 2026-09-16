rule TTP_XOR_MULT_DOSStub_1527 {
  strings:
    $key_1527 = { 41 4f [2] 35 57 [2] 72 55 [2] 35 44 [2] 7b 48 [2] 77 42 [2] 60 49 [2] 7b 07 [2] 46 }

  condition:
    any of them
}