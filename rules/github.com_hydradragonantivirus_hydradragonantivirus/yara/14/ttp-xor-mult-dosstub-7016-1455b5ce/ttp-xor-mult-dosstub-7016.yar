rule TTP_XOR_MULT_DOSStub_7016 {
  strings:
    $key_7016 = { 24 7e [2] 50 66 [2] 17 64 [2] 50 75 [2] 1e 79 [2] 12 73 [2] 05 78 [2] 1e 36 [2] 23 }

  condition:
    any of them
}