rule TTP_XOR_MULT_DOSStub_76e4 {
  strings:
    $key_76e4 = { 22 8c [2] 56 94 [2] 11 96 [2] 56 87 [2] 18 8b [2] 14 81 [2] 03 8a [2] 18 c4 [2] 25 }

  condition:
    any of them
}