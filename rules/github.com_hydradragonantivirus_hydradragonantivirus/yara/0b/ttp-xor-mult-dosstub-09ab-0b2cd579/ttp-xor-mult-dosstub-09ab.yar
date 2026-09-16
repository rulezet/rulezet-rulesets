rule TTP_XOR_MULT_DOSStub_09ab {
  strings:
    $key_09ab = { 5d c3 [2] 29 db [2] 6e d9 [2] 29 c8 [2] 67 c4 [2] 6b ce [2] 7c c5 [2] 67 8b [2] 5a }

  condition:
    any of them
}