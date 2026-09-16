rule TTP_XOR_MULT_DOSStub_5472 {
  strings:
    $key_5472 = { 00 1a [2] 74 02 [2] 33 00 [2] 74 11 [2] 3a 1d [2] 36 17 [2] 21 1c [2] 3a 52 [2] 07 }

  condition:
    any of them
}