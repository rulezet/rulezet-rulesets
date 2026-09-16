rule TTP_XOR_MULT_DOSStub_fc60 {
  strings:
    $key_fc60 = { a8 08 [2] dc 10 [2] 9b 12 [2] dc 03 [2] 92 0f [2] 9e 05 [2] 89 0e [2] 92 40 [2] af }

  condition:
    any of them
}