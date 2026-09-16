rule TTP_XOR_MULT_DOSStub_1e4b {
  strings:
    $key_1e4b = { 4a 23 [2] 3e 3b [2] 79 39 [2] 3e 28 [2] 70 24 [2] 7c 2e [2] 6b 25 [2] 70 6b [2] 4d }

  condition:
    any of them
}