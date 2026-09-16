rule TTP_XOR_MULT_DOSStub_4e4b {
  strings:
    $key_4e4b = { 1a 23 [2] 6e 3b [2] 29 39 [2] 6e 28 [2] 20 24 [2] 2c 2e [2] 3b 25 [2] 20 6b [2] 1d }

  condition:
    any of them
}