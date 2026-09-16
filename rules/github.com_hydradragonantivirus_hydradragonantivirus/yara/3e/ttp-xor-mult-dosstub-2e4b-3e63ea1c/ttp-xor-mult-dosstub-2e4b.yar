rule TTP_XOR_MULT_DOSStub_2e4b {
  strings:
    $key_2e4b = { 7a 23 [2] 0e 3b [2] 49 39 [2] 0e 28 [2] 40 24 [2] 4c 2e [2] 5b 25 [2] 40 6b [2] 7d }

  condition:
    any of them
}