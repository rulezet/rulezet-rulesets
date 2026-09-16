rule TTP_XOR_MULT_DOSStub_74e6 {
  strings:
    $key_74e6 = { 20 8e [2] 54 96 [2] 13 94 [2] 54 85 [2] 1a 89 [2] 16 83 [2] 01 88 [2] 1a c6 [2] 27 }

  condition:
    any of them
}