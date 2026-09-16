rule TTP_XOR_MULT_DOSStub_5479 {
  strings:
    $key_5479 = { 00 11 [2] 74 09 [2] 33 0b [2] 74 1a [2] 3a 16 [2] 36 1c [2] 21 17 [2] 3a 59 [2] 07 }

  condition:
    any of them
}