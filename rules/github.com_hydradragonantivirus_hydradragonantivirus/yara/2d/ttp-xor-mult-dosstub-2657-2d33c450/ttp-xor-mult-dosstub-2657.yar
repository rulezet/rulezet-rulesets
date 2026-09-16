rule TTP_XOR_MULT_DOSStub_2657 {
  strings:
    $key_2657 = { 72 3f [2] 06 27 [2] 41 25 [2] 06 34 [2] 48 38 [2] 44 32 [2] 53 39 [2] 48 77 [2] 75 }

  condition:
    any of them
}