rule TTP_XOR_MULT_DOSStub_4068 {
  strings:
    $key_4068 = { 14 00 [2] 60 18 [2] 27 1a [2] 60 0b [2] 2e 07 [2] 22 0d [2] 35 06 [2] 2e 48 [2] 13 }

  condition:
    any of them
}