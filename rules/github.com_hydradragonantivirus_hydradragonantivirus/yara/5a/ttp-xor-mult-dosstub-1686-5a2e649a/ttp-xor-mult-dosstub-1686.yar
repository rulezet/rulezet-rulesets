rule TTP_XOR_MULT_DOSStub_1686 {
  strings:
    $key_1686 = { 42 ee [2] 36 f6 [2] 71 f4 [2] 36 e5 [2] 78 e9 [2] 74 e3 [2] 63 e8 [2] 78 a6 [2] 45 }

  condition:
    any of them
}