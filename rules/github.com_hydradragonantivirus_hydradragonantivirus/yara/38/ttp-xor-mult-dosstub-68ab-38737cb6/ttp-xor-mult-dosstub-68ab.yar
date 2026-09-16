rule TTP_XOR_MULT_DOSStub_68ab {
  strings:
    $key_68ab = { 3c c3 [2] 48 db [2] 0f d9 [2] 48 c8 [2] 06 c4 [2] 0a ce [2] 1d c5 [2] 06 8b [2] 3b }

  condition:
    any of them
}