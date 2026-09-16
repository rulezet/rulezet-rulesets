rule TTP_XOR_MULT_DOSStub_45e6 {
  strings:
    $key_45e6 = { 11 8e [2] 65 96 [2] 22 94 [2] 65 85 [2] 2b 89 [2] 27 83 [2] 30 88 [2] 2b c6 [2] 16 }

  condition:
    any of them
}