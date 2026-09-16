rule TTP_XOR_MULT_DOSStub_5de6 {
  strings:
    $key_5de6 = { 09 8e [2] 7d 96 [2] 3a 94 [2] 7d 85 [2] 33 89 [2] 3f 83 [2] 28 88 [2] 33 c6 [2] 0e }

  condition:
    any of them
}