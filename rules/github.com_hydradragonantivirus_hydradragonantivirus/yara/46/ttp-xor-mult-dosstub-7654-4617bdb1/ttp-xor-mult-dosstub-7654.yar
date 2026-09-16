rule TTP_XOR_MULT_DOSStub_7654 {
  strings:
    $key_7654 = { 22 3c [2] 56 24 [2] 11 26 [2] 56 37 [2] 18 3b [2] 14 31 [2] 03 3a [2] 18 74 [2] 25 }

  condition:
    any of them
}