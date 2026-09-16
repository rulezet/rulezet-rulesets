rule TTP_XOR_MULT_DOSStub_5405 {
  strings:
    $key_5405 = { 00 6d [2] 74 75 [2] 33 77 [2] 74 66 [2] 3a 6a [2] 36 60 [2] 21 6b [2] 3a 25 [2] 07 }

  condition:
    any of them
}