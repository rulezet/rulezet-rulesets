rule TTP_XOR_MULT_DOSStub_474b {
  strings:
    $key_474b = { 13 23 [2] 67 3b [2] 20 39 [2] 67 28 [2] 29 24 [2] 25 2e [2] 32 25 [2] 29 6b [2] 14 }

  condition:
    any of them
}