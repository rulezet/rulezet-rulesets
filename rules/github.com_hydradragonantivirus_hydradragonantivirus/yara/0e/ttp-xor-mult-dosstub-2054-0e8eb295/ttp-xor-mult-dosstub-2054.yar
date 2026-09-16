rule TTP_XOR_MULT_DOSStub_2054 {
  strings:
    $key_2054 = { 74 3c [2] 00 24 [2] 47 26 [2] 00 37 [2] 4e 3b [2] 42 31 [2] 55 3a [2] 4e 74 [2] 73 }

  condition:
    any of them
}