rule TTP_XOR_MULT_DOSStub_4de6 {
  strings:
    $key_4de6 = { 19 8e [2] 6d 96 [2] 2a 94 [2] 6d 85 [2] 23 89 [2] 2f 83 [2] 38 88 [2] 23 c6 [2] 1e }

  condition:
    any of them
}