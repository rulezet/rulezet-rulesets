rule TTP_XOR_MULT_DOSStub_4c4b {
  strings:
    $key_4c4b = { 18 23 [2] 6c 3b [2] 2b 39 [2] 6c 28 [2] 22 24 [2] 2e 2e [2] 39 25 [2] 22 6b [2] 1f }

  condition:
    any of them
}