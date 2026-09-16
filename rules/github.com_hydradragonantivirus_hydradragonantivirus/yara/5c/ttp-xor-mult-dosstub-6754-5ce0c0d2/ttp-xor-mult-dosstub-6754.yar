rule TTP_XOR_MULT_DOSStub_6754 {
  strings:
    $key_6754 = { 33 3c [2] 47 24 [2] 00 26 [2] 47 37 [2] 09 3b [2] 05 31 [2] 12 3a [2] 09 74 [2] 34 }

  condition:
    any of them
}