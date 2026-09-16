rule TTP_XOR_MULT_DOSStub_084b {
  strings:
    $key_084b = { 5c 23 [2] 28 3b [2] 6f 39 [2] 28 28 [2] 66 24 [2] 6a 2e [2] 7d 25 [2] 66 6b [2] 5b }

  condition:
    any of them
}