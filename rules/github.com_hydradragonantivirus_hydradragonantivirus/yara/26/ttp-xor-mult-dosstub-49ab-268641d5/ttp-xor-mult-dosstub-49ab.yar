rule TTP_XOR_MULT_DOSStub_49ab {
  strings:
    $key_49ab = { 1d c3 [2] 69 db [2] 2e d9 [2] 69 c8 [2] 27 c4 [2] 2b ce [2] 3c c5 [2] 27 8b [2] 1a }

  condition:
    any of them
}