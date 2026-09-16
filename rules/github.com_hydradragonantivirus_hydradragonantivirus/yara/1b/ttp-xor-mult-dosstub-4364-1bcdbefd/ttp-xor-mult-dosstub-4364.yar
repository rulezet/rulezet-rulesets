rule TTP_XOR_MULT_DOSStub_4364 {
  strings:
    $key_4364 = { 17 0c [2] 63 14 [2] 24 16 [2] 63 07 [2] 2d 0b [2] 21 01 [2] 36 0a [2] 2d 44 [2] 10 }

  condition:
    any of them
}