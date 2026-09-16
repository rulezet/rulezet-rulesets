rule TTP_XOR_MULT_DOSStub_644b {
  strings:
    $key_644b = { 30 23 [2] 44 3b [2] 03 39 [2] 44 28 [2] 0a 24 [2] 06 2e [2] 11 25 [2] 0a 6b [2] 37 }

  condition:
    any of them
}