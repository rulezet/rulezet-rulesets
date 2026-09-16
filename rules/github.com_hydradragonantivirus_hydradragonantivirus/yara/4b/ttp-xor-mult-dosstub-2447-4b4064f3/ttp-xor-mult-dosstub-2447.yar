rule TTP_XOR_MULT_DOSStub_2447 {
  strings:
    $key_2447 = { 70 2f [2] 04 37 [2] 43 35 [2] 04 24 [2] 4a 28 [2] 46 22 [2] 51 29 [2] 4a 67 [2] 77 }

  condition:
    any of them
}