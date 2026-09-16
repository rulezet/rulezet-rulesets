rule TTP_XOR_MULT_DOSStub_274b {
  strings:
    $key_274b = { 73 23 [2] 07 3b [2] 40 39 [2] 07 28 [2] 49 24 [2] 45 2e [2] 52 25 [2] 49 6b [2] 74 }

  condition:
    any of them
}