rule TTP_XOR_MULT_DOSStub_5268 {
  strings:
    $key_5268 = { 06 00 [2] 72 18 [2] 35 1a [2] 72 0b [2] 3c 07 [2] 30 0d [2] 27 06 [2] 3c 48 [2] 01 }

  condition:
    any of them
}