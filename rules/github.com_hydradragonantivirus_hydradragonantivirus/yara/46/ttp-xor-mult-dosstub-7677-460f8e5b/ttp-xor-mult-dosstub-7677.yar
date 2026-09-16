rule TTP_XOR_MULT_DOSStub_7677 {
  strings:
    $key_7677 = { 22 1f [2] 56 07 [2] 11 05 [2] 56 14 [2] 18 18 [2] 14 12 [2] 03 19 [2] 18 57 [2] 25 }

  condition:
    any of them
}