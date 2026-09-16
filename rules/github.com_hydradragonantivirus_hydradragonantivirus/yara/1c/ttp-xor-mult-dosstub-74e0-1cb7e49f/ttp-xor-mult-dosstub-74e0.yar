rule TTP_XOR_MULT_DOSStub_74e0 {
  strings:
    $key_74e0 = { 20 88 [2] 54 90 [2] 13 92 [2] 54 83 [2] 1a 8f [2] 16 85 [2] 01 8e [2] 1a c0 [2] 27 }

  condition:
    any of them
}