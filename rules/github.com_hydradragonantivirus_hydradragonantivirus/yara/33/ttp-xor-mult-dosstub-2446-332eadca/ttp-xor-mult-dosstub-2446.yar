rule TTP_XOR_MULT_DOSStub_2446 {
  strings:
    $key_2446 = { 70 2e [2] 04 36 [2] 43 34 [2] 04 25 [2] 4a 29 [2] 46 23 [2] 51 28 [2] 4a 66 [2] 77 }

  condition:
    any of them
}