rule TTP_XOR_MULT_DOSStub_074b {
  strings:
    $key_074b = { 53 23 [2] 27 3b [2] 60 39 [2] 27 28 [2] 69 24 [2] 65 2e [2] 72 25 [2] 69 6b [2] 54 }

  condition:
    any of them
}