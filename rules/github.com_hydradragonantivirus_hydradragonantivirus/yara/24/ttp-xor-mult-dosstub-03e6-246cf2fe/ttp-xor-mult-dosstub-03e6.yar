rule TTP_XOR_MULT_DOSStub_03e6 {
  strings:
    $key_03e6 = { 57 8e [2] 23 96 [2] 64 94 [2] 23 85 [2] 6d 89 [2] 61 83 [2] 76 88 [2] 6d c6 [2] 50 }

  condition:
    any of them
}