rule TTP_XOR_MULT_DOSStub_4363 {
  strings:
    $key_4363 = { 17 0b [2] 63 13 [2] 24 11 [2] 63 00 [2] 2d 0c [2] 21 06 [2] 36 0d [2] 2d 43 [2] 10 }

  condition:
    any of them
}