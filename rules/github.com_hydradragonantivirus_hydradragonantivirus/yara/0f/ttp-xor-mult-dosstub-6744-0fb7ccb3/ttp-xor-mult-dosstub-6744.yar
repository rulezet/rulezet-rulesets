rule TTP_XOR_MULT_DOSStub_6744 {
  strings:
    $key_6744 = { 33 2c [2] 47 34 [2] 00 36 [2] 47 27 [2] 09 2b [2] 05 21 [2] 12 2a [2] 09 64 [2] 34 }

  condition:
    any of them
}