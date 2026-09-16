rule TTP_XOR_MULT_DOSStub_7659 {
  strings:
    $key_7659 = { 22 31 [2] 56 29 [2] 11 2b [2] 56 3a [2] 18 36 [2] 14 3c [2] 03 37 [2] 18 79 [2] 25 }

  condition:
    any of them
}