rule TTP_XOR_MULT_DOSStub_7134 {
  strings:
    $key_7134 = { 25 5c [2] 51 44 [2] 16 46 [2] 51 57 [2] 1f 5b [2] 13 51 [2] 04 5a [2] 1f 14 [2] 22 }

  condition:
    any of them
}