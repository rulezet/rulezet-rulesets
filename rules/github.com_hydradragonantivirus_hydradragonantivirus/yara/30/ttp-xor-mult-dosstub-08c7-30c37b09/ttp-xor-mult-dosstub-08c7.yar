rule TTP_XOR_MULT_DOSStub_08c7 {
  strings:
    $key_08c7 = { 5c af [2] 28 b7 [2] 6f b5 [2] 28 a4 [2] 66 a8 [2] 6a a2 [2] 7d a9 [2] 66 e7 [2] 5b }

  condition:
    any of them
}