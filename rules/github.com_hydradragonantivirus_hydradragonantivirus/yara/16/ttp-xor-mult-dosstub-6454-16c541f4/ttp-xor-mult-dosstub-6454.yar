rule TTP_XOR_MULT_DOSStub_6454 {
  strings:
    $key_6454 = { 30 3c [2] 44 24 [2] 03 26 [2] 44 37 [2] 0a 3b [2] 06 31 [2] 11 3a [2] 0a 74 [2] 37 }

  condition:
    any of them
}