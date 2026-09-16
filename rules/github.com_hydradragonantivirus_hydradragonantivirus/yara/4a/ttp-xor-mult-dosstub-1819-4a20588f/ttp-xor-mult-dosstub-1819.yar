rule TTP_XOR_MULT_DOSStub_1819 {
  strings:
    $key_1819 = { 4c 71 [2] 38 69 [2] 7f 6b [2] 38 7a [2] 76 76 [2] 7a 7c [2] 6d 77 [2] 76 39 [2] 4b }

  condition:
    any of them
}