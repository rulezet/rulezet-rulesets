rule TTP_XOR_MULT_DOSStub_40e4 {
  strings:
    $key_40e4 = { 14 8c [2] 60 94 [2] 27 96 [2] 60 87 [2] 2e 8b [2] 22 81 [2] 35 8a [2] 2e c4 [2] 13 }

  condition:
    any of them
}