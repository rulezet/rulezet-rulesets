rule TTP_XOR_MULT_DOSStub_fc34 {
  strings:
    $key_fc34 = { a8 5c [2] dc 44 [2] 9b 46 [2] dc 57 [2] 92 5b [2] 9e 51 [2] 89 5a [2] 92 14 [2] af }

  condition:
    any of them
}