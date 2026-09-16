rule TTP_XOR_MULT_DOSStub_5419 {
  strings:
    $key_5419 = { 00 71 [2] 74 69 [2] 33 6b [2] 74 7a [2] 3a 76 [2] 36 7c [2] 21 77 [2] 3a 39 [2] 07 }

  condition:
    any of them
}