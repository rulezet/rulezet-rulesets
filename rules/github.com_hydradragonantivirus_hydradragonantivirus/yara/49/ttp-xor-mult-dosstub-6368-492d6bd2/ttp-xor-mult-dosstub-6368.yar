rule TTP_XOR_MULT_DOSStub_6368 {
  strings:
    $key_6368 = { 37 00 [2] 43 18 [2] 04 1a [2] 43 0b [2] 0d 07 [2] 01 0d [2] 16 06 [2] 0d 48 [2] 30 }

  condition:
    any of them
}