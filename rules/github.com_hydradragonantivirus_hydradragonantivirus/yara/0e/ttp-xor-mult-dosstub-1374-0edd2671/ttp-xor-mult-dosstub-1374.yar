rule TTP_XOR_MULT_DOSStub_1374 {
  strings:
    $key_1374 = { 47 1c [2] 33 04 [2] 74 06 [2] 33 17 [2] 7d 1b [2] 71 11 [2] 66 1a [2] 7d 54 [2] 40 }

  condition:
    any of them
}