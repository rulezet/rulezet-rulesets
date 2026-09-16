rule TTP_XOR_MULT_DOSStub_2406 {
  strings:
    $key_2406 = { 70 6e [2] 04 76 [2] 43 74 [2] 04 65 [2] 4a 69 [2] 46 63 [2] 51 68 [2] 4a 26 [2] 77 }

  condition:
    any of them
}