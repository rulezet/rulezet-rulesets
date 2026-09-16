rule TTP_XOR_MULT_DOSStub_2437 {
  strings:
    $key_2437 = { 70 5f [2] 04 47 [2] 43 45 [2] 04 54 [2] 4a 58 [2] 46 52 [2] 51 59 [2] 4a 17 [2] 77 }

  condition:
    any of them
}