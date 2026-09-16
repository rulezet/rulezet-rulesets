rule TTP_XOR_MULT_DOSStub_5654 {
  strings:
    $key_5654 = { 02 3c [2] 76 24 [2] 31 26 [2] 76 37 [2] 38 3b [2] 34 31 [2] 23 3a [2] 38 74 [2] 05 }

  condition:
    any of them
}