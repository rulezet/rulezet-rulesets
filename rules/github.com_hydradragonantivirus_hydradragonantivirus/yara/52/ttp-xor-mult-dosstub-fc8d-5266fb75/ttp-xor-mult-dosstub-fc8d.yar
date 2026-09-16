rule TTP_XOR_MULT_DOSStub_fc8d {
  strings:
    $key_fc8d = { a8 e5 [2] dc fd [2] 9b ff [2] dc ee [2] 92 e2 [2] 9e e8 [2] 89 e3 [2] 92 ad [2] af }

  condition:
    any of them
}