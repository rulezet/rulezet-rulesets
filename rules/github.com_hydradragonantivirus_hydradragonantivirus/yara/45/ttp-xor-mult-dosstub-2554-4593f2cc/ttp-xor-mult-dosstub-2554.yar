rule TTP_XOR_MULT_DOSStub_2554 {
  strings:
    $key_2554 = { 71 3c [2] 05 24 [2] 42 26 [2] 05 37 [2] 4b 3b [2] 47 31 [2] 50 3a [2] 4b 74 [2] 76 }

  condition:
    any of them
}