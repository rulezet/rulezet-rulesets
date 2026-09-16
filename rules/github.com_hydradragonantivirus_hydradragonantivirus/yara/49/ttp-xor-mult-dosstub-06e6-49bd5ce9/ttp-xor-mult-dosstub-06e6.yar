rule TTP_XOR_MULT_DOSStub_06e6 {
  strings:
    $key_06e6 = { 52 8e [2] 26 96 [2] 61 94 [2] 26 85 [2] 68 89 [2] 64 83 [2] 73 88 [2] 68 c6 [2] 55 }

  condition:
    any of them
}