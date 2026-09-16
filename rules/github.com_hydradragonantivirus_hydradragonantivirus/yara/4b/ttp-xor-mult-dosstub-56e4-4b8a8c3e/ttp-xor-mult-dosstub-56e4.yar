rule TTP_XOR_MULT_DOSStub_56e4 {
  strings:
    $key_56e4 = { 02 8c [2] 76 94 [2] 31 96 [2] 76 87 [2] 38 8b [2] 34 81 [2] 23 8a [2] 38 c4 [2] 05 }

  condition:
    any of them
}