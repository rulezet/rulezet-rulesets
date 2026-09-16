rule TTP_XOR_MULT_DOSStub_70e6 {
  strings:
    $key_70e6 = { 24 8e [2] 50 96 [2] 17 94 [2] 50 85 [2] 1e 89 [2] 12 83 [2] 05 88 [2] 1e c6 [2] 23 }

  condition:
    any of them
}