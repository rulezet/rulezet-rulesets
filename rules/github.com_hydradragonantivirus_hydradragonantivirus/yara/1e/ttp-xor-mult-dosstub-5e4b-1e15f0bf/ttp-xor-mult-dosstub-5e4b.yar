rule TTP_XOR_MULT_DOSStub_5e4b {
  strings:
    $key_5e4b = { 0a 23 [2] 7e 3b [2] 39 39 [2] 7e 28 [2] 30 24 [2] 3c 2e [2] 2b 25 [2] 30 6b [2] 0d }

  condition:
    any of them
}