rule TTP_XOR_MULT_DOSStub_5464 {
  strings:
    $key_5464 = { 00 0c [2] 74 14 [2] 33 16 [2] 74 07 [2] 3a 0b [2] 36 01 [2] 21 0a [2] 3a 44 [2] 07 }

  condition:
    any of them
}