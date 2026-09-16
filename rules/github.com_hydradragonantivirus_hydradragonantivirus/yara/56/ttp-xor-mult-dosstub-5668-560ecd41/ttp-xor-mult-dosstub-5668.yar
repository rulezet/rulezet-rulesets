rule TTP_XOR_MULT_DOSStub_5668 {
  strings:
    $key_5668 = { 02 00 [2] 76 18 [2] 31 1a [2] 76 0b [2] 38 07 [2] 34 0d [2] 23 06 [2] 38 48 [2] 05 }

  condition:
    any of them
}