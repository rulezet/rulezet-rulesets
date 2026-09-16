rule TTP_XOR_MULT_DOSStub_2365 {
  strings:
    $key_2365 = { 77 0d [2] 03 15 [2] 44 17 [2] 03 06 [2] 4d 0a [2] 41 00 [2] 56 0b [2] 4d 45 [2] 70 }

  condition:
    any of them
}