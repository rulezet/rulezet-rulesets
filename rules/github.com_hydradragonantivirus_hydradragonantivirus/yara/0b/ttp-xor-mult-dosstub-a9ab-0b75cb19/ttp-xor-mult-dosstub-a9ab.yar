rule TTP_XOR_MULT_DOSStub_a9ab {
  strings:
    $key_a9ab = { fd c3 [2] 89 db [2] ce d9 [2] 89 c8 [2] c7 c4 [2] cb ce [2] dc c5 [2] c7 8b [2] fa }

  condition:
    any of them
}