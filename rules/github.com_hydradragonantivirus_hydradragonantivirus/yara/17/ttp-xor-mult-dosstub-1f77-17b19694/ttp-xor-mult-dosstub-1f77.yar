rule TTP_XOR_MULT_DOSStub_1f77 {
  strings:
    $key_1f77 = { 4b 1f [2] 3f 07 [2] 78 05 [2] 3f 14 [2] 71 18 [2] 7d 12 [2] 6a 19 [2] 71 57 [2] 4c }

  condition:
    any of them
}