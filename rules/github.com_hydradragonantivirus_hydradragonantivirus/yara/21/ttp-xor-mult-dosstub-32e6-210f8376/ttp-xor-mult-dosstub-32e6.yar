rule TTP_XOR_MULT_DOSStub_32e6 {
  strings:
    $key_32e6 = { 66 8e [2] 12 96 [2] 55 94 [2] 12 85 [2] 5c 89 [2] 50 83 [2] 47 88 [2] 5c c6 [2] 61 }

  condition:
    any of them
}