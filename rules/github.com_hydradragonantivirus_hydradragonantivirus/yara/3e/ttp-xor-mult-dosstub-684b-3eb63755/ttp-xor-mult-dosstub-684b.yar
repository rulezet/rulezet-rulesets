rule TTP_XOR_MULT_DOSStub_684b {
  strings:
    $key_684b = { 3c 23 [2] 48 3b [2] 0f 39 [2] 48 28 [2] 06 24 [2] 0a 2e [2] 1d 25 [2] 06 6b [2] 3b }

  condition:
    any of them
}