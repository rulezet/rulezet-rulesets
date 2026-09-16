rule TTP_XOR_MULT_DOSStub_1a54 {
  strings:
    $key_1a54 = { 4e 3c [2] 3a 24 [2] 7d 26 [2] 3a 37 [2] 74 3b [2] 78 31 [2] 6f 3a [2] 74 74 [2] 49 }

  condition:
    any of them
}