rule TTP_XOR_MULT_DOSStub_524b {
  strings:
    $key_524b = { 06 23 [2] 72 3b [2] 35 39 [2] 72 28 [2] 3c 24 [2] 30 2e [2] 27 25 [2] 3c 6b [2] 01 }

  condition:
    any of them
}