rule TTP_XOR_MULT_DOSStub_54e6 {
  strings:
    $key_54e6 = { 00 8e [2] 74 96 [2] 33 94 [2] 74 85 [2] 3a 89 [2] 36 83 [2] 21 88 [2] 3a c6 [2] 07 }

  condition:
    any of them
}