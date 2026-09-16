rule TTP_XOR_MULT_DOSStub_4ee6 {
  strings:
    $key_4ee6 = { 1a 8e [2] 6e 96 [2] 29 94 [2] 6e 85 [2] 20 89 [2] 2c 83 [2] 3b 88 [2] 20 c6 [2] 1d }

  condition:
    any of them
}