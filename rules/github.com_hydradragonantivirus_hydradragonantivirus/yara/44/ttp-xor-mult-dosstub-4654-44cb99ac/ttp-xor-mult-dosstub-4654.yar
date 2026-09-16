rule TTP_XOR_MULT_DOSStub_4654 {
  strings:
    $key_4654 = { 12 3c [2] 66 24 [2] 21 26 [2] 66 37 [2] 28 3b [2] 24 31 [2] 33 3a [2] 28 74 [2] 15 }

  condition:
    any of them
}