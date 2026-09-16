rule TTP_XOR_MULT_DOSStub_55e6 {
  strings:
    $key_55e6 = { 01 8e [2] 75 96 [2] 32 94 [2] 75 85 [2] 3b 89 [2] 37 83 [2] 20 88 [2] 3b c6 [2] 06 }

  condition:
    any of them
}