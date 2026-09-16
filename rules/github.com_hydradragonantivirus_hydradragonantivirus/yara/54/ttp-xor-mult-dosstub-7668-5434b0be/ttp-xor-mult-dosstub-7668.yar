rule TTP_XOR_MULT_DOSStub_7668 {
  strings:
    $key_7668 = { 22 00 [2] 56 18 [2] 11 1a [2] 56 0b [2] 18 07 [2] 14 0d [2] 03 06 [2] 18 48 [2] 25 }

  condition:
    any of them
}