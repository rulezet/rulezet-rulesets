rule TTP_XOR_MULT_DOSStub_4354 {
  strings:
    $key_4354 = { 17 3c [2] 63 24 [2] 24 26 [2] 63 37 [2] 2d 3b [2] 21 31 [2] 36 3a [2] 2d 74 [2] 10 }

  condition:
    any of them
}