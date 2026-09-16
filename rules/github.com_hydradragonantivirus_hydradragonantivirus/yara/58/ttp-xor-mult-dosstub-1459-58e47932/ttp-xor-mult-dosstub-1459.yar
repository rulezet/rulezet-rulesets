rule TTP_XOR_MULT_DOSStub_1459 {
  strings:
    $key_1459 = { 40 31 [2] 34 29 [2] 73 2b [2] 34 3a [2] 7a 36 [2] 76 3c [2] 61 37 [2] 7a 79 [2] 47 }

  condition:
    any of them
}