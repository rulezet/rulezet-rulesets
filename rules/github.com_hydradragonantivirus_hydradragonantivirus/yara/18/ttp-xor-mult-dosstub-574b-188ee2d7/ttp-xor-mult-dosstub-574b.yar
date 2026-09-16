rule TTP_XOR_MULT_DOSStub_574b {
  strings:
    $key_574b = { 03 23 [2] 77 3b [2] 30 39 [2] 77 28 [2] 39 24 [2] 35 2e [2] 22 25 [2] 39 6b [2] 04 }

  condition:
    any of them
}