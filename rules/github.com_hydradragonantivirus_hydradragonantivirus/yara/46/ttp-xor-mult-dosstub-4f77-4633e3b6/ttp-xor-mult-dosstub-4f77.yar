rule TTP_XOR_MULT_DOSStub_4f77 {
  strings:
    $key_4f77 = { 1b 1f [2] 6f 07 [2] 28 05 [2] 6f 14 [2] 21 18 [2] 2d 12 [2] 3a 19 [2] 21 57 [2] 1c }

  condition:
    any of them
}