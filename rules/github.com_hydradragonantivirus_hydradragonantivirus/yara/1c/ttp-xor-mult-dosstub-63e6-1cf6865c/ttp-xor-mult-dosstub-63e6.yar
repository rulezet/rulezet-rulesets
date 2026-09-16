rule TTP_XOR_MULT_DOSStub_63e6 {
  strings:
    $key_63e6 = { 37 8e [2] 43 96 [2] 04 94 [2] 43 85 [2] 0d 89 [2] 01 83 [2] 16 88 [2] 0d c6 [2] 30 }

  condition:
    any of them
}