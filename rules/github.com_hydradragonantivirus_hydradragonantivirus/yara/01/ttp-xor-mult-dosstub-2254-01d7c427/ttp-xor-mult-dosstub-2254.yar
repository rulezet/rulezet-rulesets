rule TTP_XOR_MULT_DOSStub_2254 {
  strings:
    $key_2254 = { 76 3c [2] 02 24 [2] 45 26 [2] 02 37 [2] 4c 3b [2] 40 31 [2] 57 3a [2] 4c 74 [2] 71 }

  condition:
    any of them
}