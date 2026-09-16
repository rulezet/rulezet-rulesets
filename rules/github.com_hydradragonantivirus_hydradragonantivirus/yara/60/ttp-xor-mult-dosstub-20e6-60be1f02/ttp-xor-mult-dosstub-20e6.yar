rule TTP_XOR_MULT_DOSStub_20e6 {
  strings:
    $key_20e6 = { 74 8e [2] 00 96 [2] 47 94 [2] 00 85 [2] 4e 89 [2] 42 83 [2] 55 88 [2] 4e c6 [2] 73 }

  condition:
    any of them
}