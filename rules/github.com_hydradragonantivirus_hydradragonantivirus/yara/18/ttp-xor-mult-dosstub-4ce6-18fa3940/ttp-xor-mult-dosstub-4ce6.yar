rule TTP_XOR_MULT_DOSStub_4ce6 {
  strings:
    $key_4ce6 = { 18 8e [2] 6c 96 [2] 2b 94 [2] 6c 85 [2] 22 89 [2] 2e 83 [2] 39 88 [2] 22 c6 [2] 1f }

  condition:
    any of them
}