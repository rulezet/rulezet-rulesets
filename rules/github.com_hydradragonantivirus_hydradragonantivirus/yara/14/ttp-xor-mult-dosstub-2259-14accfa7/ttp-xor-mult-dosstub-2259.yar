rule TTP_XOR_MULT_DOSStub_2259 {
  strings:
    $key_2259 = { 76 31 [2] 02 29 [2] 45 2b [2] 02 3a [2] 4c 36 [2] 40 3c [2] 57 37 [2] 4c 79 [2] 71 }

  condition:
    any of them
}