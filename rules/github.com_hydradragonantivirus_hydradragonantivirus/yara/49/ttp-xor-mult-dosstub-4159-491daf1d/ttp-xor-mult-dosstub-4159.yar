rule TTP_XOR_MULT_DOSStub_4159 {
  strings:
    $key_4159 = { 15 31 [2] 61 29 [2] 26 2b [2] 61 3a [2] 2f 36 [2] 23 3c [2] 34 37 [2] 2f 79 [2] 12 }

  condition:
    any of them
}