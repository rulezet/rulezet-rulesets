rule TTP_XOR_MULT_DOSStub_2471 {
  strings:
    $key_2471 = { 70 19 [2] 04 01 [2] 43 03 [2] 04 12 [2] 4a 1e [2] 46 14 [2] 51 1f [2] 4a 51 [2] 77 }

  condition:
    any of them
}