rule TTP_XOR_MULT_DOSStub_4659 {
  strings:
    $key_4659 = { 12 31 [2] 66 29 [2] 21 2b [2] 66 3a [2] 28 36 [2] 24 3c [2] 33 37 [2] 28 79 [2] 15 }

  condition:
    any of them
}