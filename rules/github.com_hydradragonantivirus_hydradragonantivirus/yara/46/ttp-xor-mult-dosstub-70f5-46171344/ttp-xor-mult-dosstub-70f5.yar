rule TTP_XOR_MULT_DOSStub_70f5 {
  strings:
    $key_70f5 = { 24 9d [2] 50 85 [2] 17 87 [2] 50 96 [2] 1e 9a [2] 12 90 [2] 05 9b [2] 1e d5 [2] 23 }

  condition:
    any of them
}