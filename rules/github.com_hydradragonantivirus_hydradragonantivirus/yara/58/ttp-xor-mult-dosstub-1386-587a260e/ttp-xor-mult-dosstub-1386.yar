rule TTP_XOR_MULT_DOSStub_1386 {
  strings:
    $key_1386 = { 47 ee [2] 33 f6 [2] 74 f4 [2] 33 e5 [2] 7d e9 [2] 71 e3 [2] 66 e8 [2] 7d a6 [2] 40 }

  condition:
    any of them
}