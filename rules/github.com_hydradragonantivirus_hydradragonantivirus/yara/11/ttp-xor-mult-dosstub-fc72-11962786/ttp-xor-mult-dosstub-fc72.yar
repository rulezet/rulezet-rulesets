rule TTP_XOR_MULT_DOSStub_fc72 {
  strings:
    $key_fc72 = { a8 1a [2] dc 02 [2] 9b 00 [2] dc 11 [2] 92 1d [2] 9e 17 [2] 89 1c [2] 92 52 [2] af }

  condition:
    any of them
}