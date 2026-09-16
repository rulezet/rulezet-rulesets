rule TTP_XOR_MULT_DOSStub_2320 {
  strings:
    $key_2320 = { 77 48 [2] 03 50 [2] 44 52 [2] 03 43 [2] 4d 4f [2] 41 45 [2] 56 4e [2] 4d 00 [2] 70 }

  condition:
    any of them
}