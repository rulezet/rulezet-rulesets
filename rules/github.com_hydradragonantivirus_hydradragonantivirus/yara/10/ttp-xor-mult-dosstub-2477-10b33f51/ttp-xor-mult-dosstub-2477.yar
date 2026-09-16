rule TTP_XOR_MULT_DOSStub_2477 {
  strings:
    $key_2477 = { 70 1f [2] 04 07 [2] 43 05 [2] 04 14 [2] 4a 18 [2] 46 12 [2] 51 19 [2] 4a 57 [2] 77 }

  condition:
    any of them
}