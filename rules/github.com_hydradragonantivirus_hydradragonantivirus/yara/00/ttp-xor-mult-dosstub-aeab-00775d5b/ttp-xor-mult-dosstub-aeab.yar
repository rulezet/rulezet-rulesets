rule TTP_XOR_MULT_DOSStub_aeab {
  strings:
    $key_aeab = { fa c3 [2] 8e db [2] c9 d9 [2] 8e c8 [2] c0 c4 [2] cc ce [2] db c5 [2] c0 8b [2] fd }

  condition:
    any of them
}