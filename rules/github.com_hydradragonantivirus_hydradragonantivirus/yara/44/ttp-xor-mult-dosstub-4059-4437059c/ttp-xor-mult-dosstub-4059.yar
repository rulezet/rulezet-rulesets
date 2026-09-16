rule TTP_XOR_MULT_DOSStub_4059 {
  strings:
    $key_4059 = { 14 31 [2] 60 29 [2] 27 2b [2] 60 3a [2] 2e 36 [2] 22 3c [2] 35 37 [2] 2e 79 [2] 13 }

  condition:
    any of them
}