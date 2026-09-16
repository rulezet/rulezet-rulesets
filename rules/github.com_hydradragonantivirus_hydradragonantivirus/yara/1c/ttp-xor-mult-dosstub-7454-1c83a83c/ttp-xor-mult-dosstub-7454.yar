rule TTP_XOR_MULT_DOSStub_7454 {
  strings:
    $key_7454 = { 20 3c [2] 54 24 [2] 13 26 [2] 54 37 [2] 1a 3b [2] 16 31 [2] 01 3a [2] 1a 74 [2] 27 }

  condition:
    any of them
}