rule TTP_XOR_MULT_DOSStub_7554 {
  strings:
    $key_7554 = { 21 3c [2] 55 24 [2] 12 26 [2] 55 37 [2] 1b 3b [2] 17 31 [2] 00 3a [2] 1b 74 [2] 26 }

  condition:
    any of them
}