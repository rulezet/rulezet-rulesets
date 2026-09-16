rule TTP_XOR_MULT_DOSStub_4568 {
  strings:
    $key_4568 = { 11 00 [2] 65 18 [2] 22 1a [2] 65 0b [2] 2b 07 [2] 27 0d [2] 30 06 [2] 2b 48 [2] 16 }

  condition:
    any of them
}