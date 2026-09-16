rule TTP_XOR_MULT_DOSStub_2370 {
  strings:
    $key_2370 = { 77 18 [2] 03 00 [2] 44 02 [2] 03 13 [2] 4d 1f [2] 41 15 [2] 56 1e [2] 4d 50 [2] 70 }

  condition:
    any of them
}