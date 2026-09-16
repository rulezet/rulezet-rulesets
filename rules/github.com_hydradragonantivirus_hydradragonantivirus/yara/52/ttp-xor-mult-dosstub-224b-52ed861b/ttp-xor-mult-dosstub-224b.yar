rule TTP_XOR_MULT_DOSStub_224b {
  strings:
    $key_224b = { 76 23 [2] 02 3b [2] 45 39 [2] 02 28 [2] 4c 24 [2] 40 2e [2] 57 25 [2] 4c 6b [2] 71 }

  condition:
    any of them
}