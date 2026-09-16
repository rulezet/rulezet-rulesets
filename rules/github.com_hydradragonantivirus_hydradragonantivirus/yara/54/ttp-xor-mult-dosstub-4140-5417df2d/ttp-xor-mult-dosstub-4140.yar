rule TTP_XOR_MULT_DOSStub_4140 {
  strings:
    $key_4140 = { 15 28 [2] 61 30 [2] 26 32 [2] 61 23 [2] 2f 2f [2] 23 25 [2] 34 2e [2] 2f 60 [2] 12 }

  condition:
    any of them
}