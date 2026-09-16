rule TTP_XOR_MULT_DOSStub_5468 {
  strings:
    $key_5468 = { 00 00 [2] 74 18 [2] 33 1a [2] 74 0b [2] 3a 07 [2] 36 0d [2] 21 06 [2] 3a 48 [2] 07 }

  condition:
    any of them
}