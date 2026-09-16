rule TTP_XOR_MULT_DOSStub_40e9 {
  strings:
    $key_40e9 = { 14 81 [2] 60 99 [2] 27 9b [2] 60 8a [2] 2e 86 [2] 22 8c [2] 35 87 [2] 2e c9 [2] 13 }

  condition:
    any of them
}