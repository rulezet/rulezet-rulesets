rule TTP_XOR_MULT_DOSStub_38ab {
  strings:
    $key_38ab = { 6c c3 [2] 18 db [2] 5f d9 [2] 18 c8 [2] 56 c4 [2] 5a ce [2] 4d c5 [2] 56 8b [2] 6b }

  condition:
    any of them
}