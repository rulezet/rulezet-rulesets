rule TTP_XOR_MULT_DOSStub_2426 {
  strings:
    $key_2426 = { 70 4e [2] 04 56 [2] 43 54 [2] 04 45 [2] 4a 49 [2] 46 43 [2] 51 48 [2] 4a 06 [2] 77 }

  condition:
    any of them
}