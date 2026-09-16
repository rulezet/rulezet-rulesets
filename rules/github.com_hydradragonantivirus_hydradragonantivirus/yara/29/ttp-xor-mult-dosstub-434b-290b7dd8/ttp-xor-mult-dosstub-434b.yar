rule TTP_XOR_MULT_DOSStub_434b {
  strings:
    $key_434b = { 17 23 [2] 63 3b [2] 24 39 [2] 63 28 [2] 2d 24 [2] 21 2e [2] 36 25 [2] 2d 6b [2] 10 }

  condition:
    any of them
}