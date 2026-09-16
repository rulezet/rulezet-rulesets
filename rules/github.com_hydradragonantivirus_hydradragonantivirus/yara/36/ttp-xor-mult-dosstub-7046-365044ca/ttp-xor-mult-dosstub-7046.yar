rule TTP_XOR_MULT_DOSStub_7046 {
  strings:
    $key_7046 = { 24 2e [2] 50 36 [2] 17 34 [2] 50 25 [2] 1e 29 [2] 12 23 [2] 05 28 [2] 1e 66 [2] 23 }

  condition:
    any of them
}