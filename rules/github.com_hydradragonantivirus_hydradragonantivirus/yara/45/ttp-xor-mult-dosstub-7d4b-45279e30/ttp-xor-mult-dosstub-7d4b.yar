rule TTP_XOR_MULT_DOSStub_7d4b {
  strings:
    $key_7d4b = { 29 23 [2] 5d 3b [2] 1a 39 [2] 5d 28 [2] 13 24 [2] 1f 2e [2] 08 25 [2] 13 6b [2] 2e }

  condition:
    any of them
}