rule TTP_XOR_MULT_DOSStub_5f77 {
  strings:
    $key_5f77 = { 0b 1f [2] 7f 07 [2] 38 05 [2] 7f 14 [2] 31 18 [2] 3d 12 [2] 2a 19 [2] 31 57 [2] 0c }

  condition:
    any of them
}