rule TTP_XOR_MULT_DOSStub_2427 {
  strings:
    $key_2427 = { 70 4f [2] 04 57 [2] 43 55 [2] 04 44 [2] 4a 48 [2] 46 42 [2] 51 49 [2] 4a 07 [2] 77 }

  condition:
    any of them
}