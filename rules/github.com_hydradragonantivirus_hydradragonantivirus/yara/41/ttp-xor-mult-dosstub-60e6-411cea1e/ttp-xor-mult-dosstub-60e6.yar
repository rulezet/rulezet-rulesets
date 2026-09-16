rule TTP_XOR_MULT_DOSStub_60e6 {
  strings:
    $key_60e6 = { 34 8e [2] 40 96 [2] 07 94 [2] 40 85 [2] 0e 89 [2] 02 83 [2] 15 88 [2] 0e c6 [2] 33 }

  condition:
    any of them
}