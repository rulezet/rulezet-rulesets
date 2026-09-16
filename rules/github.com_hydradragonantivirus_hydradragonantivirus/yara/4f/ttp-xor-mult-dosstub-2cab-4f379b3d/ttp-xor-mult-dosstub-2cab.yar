rule TTP_XOR_MULT_DOSStub_2cab {
  strings:
    $key_2cab = { 78 c3 [2] 0c db [2] 4b d9 [2] 0c c8 [2] 42 c4 [2] 4e ce [2] 59 c5 [2] 42 8b [2] 7f }

  condition:
    any of them
}