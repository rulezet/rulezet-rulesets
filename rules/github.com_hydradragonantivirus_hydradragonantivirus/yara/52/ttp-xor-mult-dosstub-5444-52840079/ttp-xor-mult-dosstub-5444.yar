rule TTP_XOR_MULT_DOSStub_5444 {
  strings:
    $key_5444 = { 00 2c [2] 74 34 [2] 33 36 [2] 74 27 [2] 3a 2b [2] 36 21 [2] 21 2a [2] 3a 64 [2] 07 }

  condition:
    any of them
}