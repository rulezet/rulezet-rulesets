rule TTP_XOR_MULT_DOSStub_3168 {
  strings:
    $key_3168 = { 65 00 [2] 11 18 [2] 56 1a [2] 11 0b [2] 5f 07 [2] 53 0d [2] 44 06 [2] 5f 48 [2] 62 }

  condition:
    any of them
}