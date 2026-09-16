rule TTP_XOR_MULT_DOSStub_1a34 {
  strings:
    $key_1a34 = { 4e 5c [2] 3a 44 [2] 7d 46 [2] 3a 57 [2] 74 5b [2] 78 51 [2] 6f 5a [2] 74 14 [2] 49 }

  condition:
    any of them
}