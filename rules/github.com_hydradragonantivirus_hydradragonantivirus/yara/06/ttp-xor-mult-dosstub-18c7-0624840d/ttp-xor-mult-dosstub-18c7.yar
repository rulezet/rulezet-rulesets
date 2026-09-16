rule TTP_XOR_MULT_DOSStub_18c7 {
  strings:
    $key_18c7 = { 4c af [2] 38 b7 [2] 7f b5 [2] 38 a4 [2] 76 a8 [2] 7a a2 [2] 6d a9 [2] 76 e7 [2] 4b }

  condition:
    any of them
}