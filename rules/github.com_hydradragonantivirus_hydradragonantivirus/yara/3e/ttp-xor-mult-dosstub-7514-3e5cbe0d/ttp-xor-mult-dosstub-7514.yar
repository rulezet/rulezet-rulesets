rule TTP_XOR_MULT_DOSStub_7514 {
  strings:
    $key_7514 = { 21 7c [2] 55 64 [2] 12 66 [2] 55 77 [2] 1b 7b [2] 17 71 [2] 00 7a [2] 1b 34 [2] 26 }

  condition:
    any of them
}