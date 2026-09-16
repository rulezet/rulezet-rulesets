rule TTP_XOR_MULT_DOSStub_7354 {
  strings:
    $key_7354 = { 27 3c [2] 53 24 [2] 14 26 [2] 53 37 [2] 1d 3b [2] 11 31 [2] 06 3a [2] 1d 74 [2] 20 }

  condition:
    any of them
}