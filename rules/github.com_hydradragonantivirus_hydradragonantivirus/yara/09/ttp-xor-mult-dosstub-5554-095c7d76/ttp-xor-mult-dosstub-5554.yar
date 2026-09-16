rule TTP_XOR_MULT_DOSStub_5554 {
  strings:
    $key_5554 = { 01 3c [2] 75 24 [2] 32 26 [2] 75 37 [2] 3b 3b [2] 37 31 [2] 20 3a [2] 3b 74 [2] 06 }

  condition:
    any of them
}