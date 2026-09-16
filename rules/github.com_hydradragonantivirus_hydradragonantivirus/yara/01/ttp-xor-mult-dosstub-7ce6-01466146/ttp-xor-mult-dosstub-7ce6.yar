rule TTP_XOR_MULT_DOSStub_7ce6 {
  strings:
    $key_7ce6 = { 28 8e [2] 5c 96 [2] 1b 94 [2] 5c 85 [2] 12 89 [2] 1e 83 [2] 09 88 [2] 12 c6 [2] 2f }

  condition:
    any of them
}