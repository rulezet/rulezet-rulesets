rule TTP_XOR_MULT_DOSStub_7de6 {
  strings:
    $key_7de6 = { 29 8e [2] 5d 96 [2] 1a 94 [2] 5d 85 [2] 13 89 [2] 1f 83 [2] 08 88 [2] 13 c6 [2] 2e }

  condition:
    any of them
}