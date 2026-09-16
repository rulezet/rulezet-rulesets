rule TTP_XOR_MULT_DOSStub_6477 {
  strings:
    $key_6477 = { 30 1f [2] 44 07 [2] 03 05 [2] 44 14 [2] 0a 18 [2] 06 12 [2] 11 19 [2] 0a 57 [2] 37 }

  condition:
    any of them
}