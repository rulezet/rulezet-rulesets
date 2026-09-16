rule TTP_XOR_MULT_DOSStub_8f8b {
  strings:
    $key_8f8b = { db e3 [2] af fb [2] e8 f9 [2] af e8 [2] e1 e4 [2] ed ee [2] fa e5 [2] e1 ab [2] dc }

  condition:
    any of them
}