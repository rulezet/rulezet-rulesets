rule TTP_XOR_MULT_DOSStub_1a59 {
  strings:
    $key_1a59 = { 4e 31 [2] 3a 29 [2] 7d 2b [2] 3a 3a [2] 74 36 [2] 78 3c [2] 6f 37 [2] 74 79 [2] 49 }

  condition:
    any of them
}