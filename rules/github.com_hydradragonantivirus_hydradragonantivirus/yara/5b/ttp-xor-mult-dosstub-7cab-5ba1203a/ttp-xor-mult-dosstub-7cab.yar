rule TTP_XOR_MULT_DOSStub_7cab {
  strings:
    $key_7cab = { 28 c3 [2] 5c db [2] 1b d9 [2] 5c c8 [2] 12 c4 [2] 1e ce [2] 09 c5 [2] 12 8b [2] 2f }

  condition:
    any of them
}