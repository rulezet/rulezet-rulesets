rule TTP_XOR_MULT_DOSStub_79ab {
  strings:
    $key_79ab = { 2d c3 [2] 59 db [2] 1e d9 [2] 59 c8 [2] 17 c4 [2] 1b ce [2] 0c c5 [2] 17 8b [2] 2a }

  condition:
    any of them
}