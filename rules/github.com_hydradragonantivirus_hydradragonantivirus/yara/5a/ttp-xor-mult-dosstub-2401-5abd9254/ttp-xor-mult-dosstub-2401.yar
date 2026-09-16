rule TTP_XOR_MULT_DOSStub_2401 {
  strings:
    $key_2401 = { 70 69 [2] 04 71 [2] 43 73 [2] 04 62 [2] 4a 6e [2] 46 64 [2] 51 6f [2] 4a 21 [2] 77 }

  condition:
    any of them
}