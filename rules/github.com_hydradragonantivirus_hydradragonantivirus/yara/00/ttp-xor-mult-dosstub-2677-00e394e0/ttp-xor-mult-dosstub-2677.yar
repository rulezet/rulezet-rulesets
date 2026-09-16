rule TTP_XOR_MULT_DOSStub_2677 {
  strings:
    $key_2677 = { 72 1f [2] 06 07 [2] 41 05 [2] 06 14 [2] 48 18 [2] 44 12 [2] 53 19 [2] 48 57 [2] 75 }

  condition:
    any of them
}