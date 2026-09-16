rule TTP_XOR_MULT_DOSStub_7365 {
  strings:
    $key_7365 = { 27 0d [2] 53 15 [2] 14 17 [2] 53 06 [2] 1d 0a [2] 11 00 [2] 06 0b [2] 1d 45 [2] 20 }

  condition:
    any of them
}