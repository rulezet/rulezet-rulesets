rule TTP_XOR_MULT_DOSStub_2441 {
  strings:
    $key_2441 = { 70 29 [2] 04 31 [2] 43 33 [2] 04 22 [2] 4a 2e [2] 46 24 [2] 51 2f [2] 4a 61 [2] 77 }

  condition:
    any of them
}