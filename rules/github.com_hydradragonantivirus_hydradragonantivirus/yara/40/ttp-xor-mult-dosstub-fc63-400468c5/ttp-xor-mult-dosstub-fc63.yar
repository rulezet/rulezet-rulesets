rule TTP_XOR_MULT_DOSStub_fc63 {
  strings:
    $key_fc63 = { a8 0b [2] dc 13 [2] 9b 11 [2] dc 00 [2] 92 0c [2] 9e 06 [2] 89 0d [2] 92 43 [2] af }

  condition:
    any of them
}