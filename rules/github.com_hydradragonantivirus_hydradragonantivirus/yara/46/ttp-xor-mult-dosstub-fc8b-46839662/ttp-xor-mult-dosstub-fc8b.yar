rule TTP_XOR_MULT_DOSStub_fc8b {
  strings:
    $key_fc8b = { a8 e3 [2] dc fb [2] 9b f9 [2] dc e8 [2] 92 e4 [2] 9e ee [2] 89 e5 [2] 92 ab [2] af }

  condition:
    any of them
}