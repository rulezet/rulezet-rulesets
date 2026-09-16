rule TTP_XOR_MULT_DOSStub_7dab {
  strings:
    $key_7dab = { 29 c3 [2] 5d db [2] 1a d9 [2] 5d c8 [2] 13 c4 [2] 1f ce [2] 08 c5 [2] 13 8b [2] 2e }

  condition:
    any of them
}