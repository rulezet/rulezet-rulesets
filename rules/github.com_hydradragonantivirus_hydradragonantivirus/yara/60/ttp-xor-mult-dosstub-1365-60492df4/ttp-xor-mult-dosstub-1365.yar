rule TTP_XOR_MULT_DOSStub_1365 {
  strings:
    $key_1365 = { 47 0d [2] 33 15 [2] 74 17 [2] 33 06 [2] 7d 0a [2] 71 00 [2] 66 0b [2] 7d 45 [2] 40 }

  condition:
    any of them
}