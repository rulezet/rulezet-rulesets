rule TTP_XOR_MULT_DOSStub_7534 {
  strings:
    $key_7534 = { 21 5c [2] 55 44 [2] 12 46 [2] 55 57 [2] 1b 5b [2] 17 51 [2] 00 5a [2] 1b 14 [2] 26 }

  condition:
    any of them
}