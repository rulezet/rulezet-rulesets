rule TTP_XOR_MULT_DOSStub_18ab {
  strings:
    $key_18ab = { 4c c3 [2] 38 db [2] 7f d9 [2] 38 c8 [2] 76 c4 [2] 7a ce [2] 6d c5 [2] 76 8b [2] 4b }

  condition:
    any of them
}