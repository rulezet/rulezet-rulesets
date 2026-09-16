rule TTP_XOR_MULT_DOSStub_fc9a {
  strings:
    $key_fc9a = { a8 f2 [2] dc ea [2] 9b e8 [2] dc f9 [2] 92 f5 [2] 9e ff [2] 89 f4 [2] 92 ba [2] af }

  condition:
    any of them
}