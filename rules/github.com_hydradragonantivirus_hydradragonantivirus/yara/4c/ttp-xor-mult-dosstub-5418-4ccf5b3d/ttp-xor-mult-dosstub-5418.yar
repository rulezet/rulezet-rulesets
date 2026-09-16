rule TTP_XOR_MULT_DOSStub_5418 {
  strings:
    $key_5418 = { 00 70 [2] 74 68 [2] 33 6a [2] 74 7b [2] 3a 77 [2] 36 7d [2] 21 76 [2] 3a 38 [2] 07 }

  condition:
    any of them
}