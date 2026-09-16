rule TTP_XOR_MULT_DOSStub_fc64 {
  strings:
    $key_fc64 = { a8 0c [2] dc 14 [2] 9b 16 [2] dc 07 [2] 92 0b [2] 9e 01 [2] 89 0a [2] 92 44 [2] af }

  condition:
    any of them
}