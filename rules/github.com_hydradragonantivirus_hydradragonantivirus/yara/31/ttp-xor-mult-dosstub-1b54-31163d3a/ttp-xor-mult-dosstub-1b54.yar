rule TTP_XOR_MULT_DOSStub_1b54 {
  strings:
    $key_1b54 = { 4f 3c [2] 3b 24 [2] 7c 26 [2] 3b 37 [2] 75 3b [2] 79 31 [2] 6e 3a [2] 75 74 [2] 48 }

  condition:
    any of them
}