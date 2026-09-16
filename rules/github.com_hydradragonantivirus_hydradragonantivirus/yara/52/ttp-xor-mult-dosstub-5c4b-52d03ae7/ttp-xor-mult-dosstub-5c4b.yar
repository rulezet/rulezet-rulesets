rule TTP_XOR_MULT_DOSStub_5c4b {
  strings:
    $key_5c4b = { 08 23 [2] 7c 3b [2] 3b 39 [2] 7c 28 [2] 32 24 [2] 3e 2e [2] 29 25 [2] 32 6b [2] 0f }

  condition:
    any of them
}