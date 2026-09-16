rule TTP_XOR_MULT_DOSStub_4dab {
  strings:
    $key_4dab = { 19 c3 [2] 6d db [2] 2a d9 [2] 6d c8 [2] 23 c4 [2] 2f ce [2] 38 c5 [2] 23 8b [2] 1e }

  condition:
    any of them
}