rule TTP_XOR_MULT_DOSStub_2430 {
  strings:
    $key_2430 = { 70 58 [2] 04 40 [2] 43 42 [2] 04 53 [2] 4a 5f [2] 46 55 [2] 51 5e [2] 4a 10 [2] 77 }

  condition:
    any of them
}