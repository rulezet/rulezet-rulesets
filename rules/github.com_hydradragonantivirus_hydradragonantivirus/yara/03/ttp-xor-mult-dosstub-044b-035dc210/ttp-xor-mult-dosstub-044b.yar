rule TTP_XOR_MULT_DOSStub_044b {
  strings:
    $key_044b = { 50 23 [2] 24 3b [2] 63 39 [2] 24 28 [2] 6a 24 [2] 66 2e [2] 71 25 [2] 6a 6b [2] 57 }

  condition:
    any of them
}