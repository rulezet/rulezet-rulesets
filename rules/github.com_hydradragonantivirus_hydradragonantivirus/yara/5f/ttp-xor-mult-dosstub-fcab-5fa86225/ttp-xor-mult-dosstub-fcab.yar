rule TTP_XOR_MULT_DOSStub_fcab {
  strings:
    $key_fcab = { a8 c3 [2] dc db [2] 9b d9 [2] dc c8 [2] 92 c4 [2] 9e ce [2] 89 c5 [2] 92 8b [2] af }

  condition:
    any of them
}