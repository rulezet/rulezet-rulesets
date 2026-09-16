rule TTP_XOR_MULT_DOSStub_5cab {
  strings:
    $key_5cab = { 08 c3 [2] 7c db [2] 3b d9 [2] 7c c8 [2] 32 c4 [2] 3e ce [2] 29 c5 [2] 32 8b [2] 0f }

  condition:
    any of them
}