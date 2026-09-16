rule TTP_XOR_MULT_DOSStub_2e86 {
  strings:
    $key_2e86 = { 7a ee [2] 0e f6 [2] 49 f4 [2] 0e e5 [2] 40 e9 [2] 4c e3 [2] 5b e8 [2] 40 a6 [2] 7d }

  condition:
    any of them
}