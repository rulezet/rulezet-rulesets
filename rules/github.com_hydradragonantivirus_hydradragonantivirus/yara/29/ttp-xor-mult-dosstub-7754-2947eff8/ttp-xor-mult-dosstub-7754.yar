rule TTP_XOR_MULT_DOSStub_7754 {
  strings:
    $key_7754 = { 23 3c [2] 57 24 [2] 10 26 [2] 57 37 [2] 19 3b [2] 15 31 [2] 02 3a [2] 19 74 [2] 24 }

  condition:
    any of them
}