rule TTP_XOR_MULT_DOSStub_fc75 {
  strings:
    $key_fc75 = { a8 1d [2] dc 05 [2] 9b 07 [2] dc 16 [2] 92 1a [2] 9e 10 [2] 89 1b [2] 92 55 [2] af }

  condition:
    any of them
}