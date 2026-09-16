rule TTP_XOR_MULT_DOSStub_67e6 {
  strings:
    $key_67e6 = { 33 8e [2] 47 96 [2] 00 94 [2] 47 85 [2] 09 89 [2] 05 83 [2] 12 88 [2] 09 c6 [2] 34 }

  condition:
    any of them
}