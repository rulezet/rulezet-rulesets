rule TTP_XOR_MULT_DOSStub_2331 {
  strings:
    $key_2331 = { 77 59 [2] 03 41 [2] 44 43 [2] 03 52 [2] 4d 5e [2] 41 54 [2] 56 5f [2] 4d 11 [2] 70 }

  condition:
    any of them
}