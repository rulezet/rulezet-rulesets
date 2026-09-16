rule TTP_XOR_MULT_DOSStub_5568 {
  strings:
    $key_5568 = { 01 00 [2] 75 18 [2] 32 1a [2] 75 0b [2] 3b 07 [2] 37 0d [2] 20 06 [2] 3b 48 [2] 06 }

  condition:
    any of them
}