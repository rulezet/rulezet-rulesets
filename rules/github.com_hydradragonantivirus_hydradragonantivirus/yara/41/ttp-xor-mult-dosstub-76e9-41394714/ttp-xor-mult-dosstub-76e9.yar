rule TTP_XOR_MULT_DOSStub_76e9 {
  strings:
    $key_76e9 = { 22 81 [2] 56 99 [2] 11 9b [2] 56 8a [2] 18 86 [2] 14 8c [2] 03 87 [2] 18 c9 [2] 25 }

  condition:
    any of them
}