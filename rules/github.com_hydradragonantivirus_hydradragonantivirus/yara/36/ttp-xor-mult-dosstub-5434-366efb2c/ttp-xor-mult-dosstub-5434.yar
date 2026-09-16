rule TTP_XOR_MULT_DOSStub_5434 {
  strings:
    $key_5434 = { 00 5c [2] 74 44 [2] 33 46 [2] 74 57 [2] 3a 5b [2] 36 51 [2] 21 5a [2] 3a 14 [2] 07 }

  condition:
    any of them
}