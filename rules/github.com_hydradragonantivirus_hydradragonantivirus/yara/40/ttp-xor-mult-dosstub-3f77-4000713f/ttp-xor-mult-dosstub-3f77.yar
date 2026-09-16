rule TTP_XOR_MULT_DOSStub_3f77 {
  strings:
    $key_3f77 = { 6b 1f [2] 1f 07 [2] 58 05 [2] 1f 14 [2] 51 18 [2] 5d 12 [2] 4a 19 [2] 51 57 [2] 6c }

  condition:
    any of them
}