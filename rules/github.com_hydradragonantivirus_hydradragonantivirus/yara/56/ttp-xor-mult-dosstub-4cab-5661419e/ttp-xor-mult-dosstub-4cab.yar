rule TTP_XOR_MULT_DOSStub_4cab {
  strings:
    $key_4cab = { 18 c3 [2] 6c db [2] 2b d9 [2] 6c c8 [2] 22 c4 [2] 2e ce [2] 39 c5 [2] 22 8b [2] 1f }

  condition:
    any of them
}