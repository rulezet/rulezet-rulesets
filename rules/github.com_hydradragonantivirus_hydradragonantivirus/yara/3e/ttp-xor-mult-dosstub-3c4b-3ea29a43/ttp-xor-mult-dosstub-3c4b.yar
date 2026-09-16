rule TTP_XOR_MULT_DOSStub_3c4b {
  strings:
    $key_3c4b = { 68 23 [2] 1c 3b [2] 5b 39 [2] 1c 28 [2] 52 24 [2] 5e 2e [2] 49 25 [2] 52 6b [2] 6f }

  condition:
    any of them
}