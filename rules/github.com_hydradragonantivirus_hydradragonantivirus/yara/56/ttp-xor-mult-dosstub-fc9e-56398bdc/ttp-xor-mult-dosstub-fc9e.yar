rule TTP_XOR_MULT_DOSStub_fc9e {
  strings:
    $key_fc9e = { a8 f6 [2] dc ee [2] 9b ec [2] dc fd [2] 92 f1 [2] 9e fb [2] 89 f0 [2] 92 be [2] af }

  condition:
    any of them
}