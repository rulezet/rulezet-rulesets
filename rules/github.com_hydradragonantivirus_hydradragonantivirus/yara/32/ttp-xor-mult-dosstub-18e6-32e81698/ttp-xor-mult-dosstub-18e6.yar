rule TTP_XOR_MULT_DOSStub_18e6 {
  strings:
    $key_18e6 = { 4c 8e [2] 38 96 [2] 7f 94 [2] 38 85 [2] 76 89 [2] 7a 83 [2] 6d 88 [2] 76 c6 [2] 4b }

  condition:
    any of them
}