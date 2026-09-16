rule TTP_XOR_MULT_DOSStub_76f5 {
  strings:
    $key_76f5 = { 22 9d [2] 56 85 [2] 11 87 [2] 56 96 [2] 18 9a [2] 14 90 [2] 03 9b [2] 18 d5 [2] 25 }

  condition:
    any of them
}