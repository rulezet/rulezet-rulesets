rule TTP_XOR_MULT_DOSStub_feab {
  strings:
    $key_feab = { aa c3 [2] de db [2] 99 d9 [2] de c8 [2] 90 c4 [2] 9c ce [2] 8b c5 [2] 90 8b [2] ad }

  condition:
    any of them
}