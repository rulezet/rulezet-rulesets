rule TTP_XOR_MULT_DOSStub_6cab {
  strings:
    $key_6cab = { 38 c3 [2] 4c db [2] 0b d9 [2] 4c c8 [2] 02 c4 [2] 0e ce [2] 19 c5 [2] 02 8b [2] 3f }

  condition:
    any of them
}