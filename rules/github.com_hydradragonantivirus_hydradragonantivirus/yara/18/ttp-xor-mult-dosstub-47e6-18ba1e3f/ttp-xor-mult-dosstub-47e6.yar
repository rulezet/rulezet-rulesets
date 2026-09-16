rule TTP_XOR_MULT_DOSStub_47e6 {
  strings:
    $key_47e6 = { 13 8e [2] 67 96 [2] 20 94 [2] 67 85 [2] 29 89 [2] 25 83 [2] 32 88 [2] 29 c6 [2] 14 }

  condition:
    any of them
}