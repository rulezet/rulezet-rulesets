rule TTP_XOR_MULT_DOSStub_5054 {
  strings:
    $key_5054 = { 04 3c [2] 70 24 [2] 37 26 [2] 70 37 [2] 3e 3b [2] 32 31 [2] 25 3a [2] 3e 74 [2] 03 }

  condition:
    any of them
}