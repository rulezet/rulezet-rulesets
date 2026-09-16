rule TTP_XOR_MULT_DOSStub_1ae6 {
  strings:
    $key_1ae6 = { 4e 8e [2] 3a 96 [2] 7d 94 [2] 3a 85 [2] 74 89 [2] 78 83 [2] 6f 88 [2] 74 c6 [2] 49 }

  condition:
    any of them
}