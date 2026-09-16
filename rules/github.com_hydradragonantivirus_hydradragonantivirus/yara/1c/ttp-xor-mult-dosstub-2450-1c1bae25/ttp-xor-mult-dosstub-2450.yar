rule TTP_XOR_MULT_DOSStub_2450 {
  strings:
    $key_2450 = { 70 38 [2] 04 20 [2] 43 22 [2] 04 33 [2] 4a 3f [2] 46 35 [2] 51 3e [2] 4a 70 [2] 77 }

  condition:
    any of them
}