rule TTP_XOR_MULT_DOSStub_56e9 {
  strings:
    $key_56e9 = { 02 81 [2] 76 99 [2] 31 9b [2] 76 8a [2] 38 86 [2] 34 8c [2] 23 87 [2] 38 c9 [2] 05 }

  condition:
    any of them
}