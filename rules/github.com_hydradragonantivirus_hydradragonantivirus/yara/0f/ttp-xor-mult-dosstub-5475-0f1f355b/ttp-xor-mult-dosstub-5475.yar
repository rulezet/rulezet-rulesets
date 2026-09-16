rule TTP_XOR_MULT_DOSStub_5475 {
  strings:
    $key_5475 = { 00 1d [2] 74 05 [2] 33 07 [2] 74 16 [2] 3a 1a [2] 36 10 [2] 21 1b [2] 3a 55 [2] 07 }

  condition:
    any of them
}