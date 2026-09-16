rule TTP_XOR_MULT_DOSStub_254b {
  strings:
    $key_254b = { 71 23 [2] 05 3b [2] 42 39 [2] 05 28 [2] 4b 24 [2] 47 2e [2] 50 25 [2] 4b 6b [2] 76 }

  condition:
    any of them
}