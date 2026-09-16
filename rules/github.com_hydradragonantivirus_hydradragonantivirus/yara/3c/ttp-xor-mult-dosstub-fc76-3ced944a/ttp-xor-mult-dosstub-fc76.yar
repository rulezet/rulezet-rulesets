rule TTP_XOR_MULT_DOSStub_fc76 {
  strings:
    $key_fc76 = { a8 1e [2] dc 06 [2] 9b 04 [2] dc 15 [2] 92 19 [2] 9e 13 [2] 89 18 [2] 92 56 [2] af }

  condition:
    any of them
}