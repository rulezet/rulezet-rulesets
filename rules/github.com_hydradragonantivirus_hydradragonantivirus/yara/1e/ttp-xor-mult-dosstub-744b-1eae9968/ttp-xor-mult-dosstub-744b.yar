rule TTP_XOR_MULT_DOSStub_744b {
  strings:
    $key_744b = { 20 23 [2] 54 3b [2] 13 39 [2] 54 28 [2] 1a 24 [2] 16 2e [2] 01 25 [2] 1a 6b [2] 27 }

  condition:
    any of them
}