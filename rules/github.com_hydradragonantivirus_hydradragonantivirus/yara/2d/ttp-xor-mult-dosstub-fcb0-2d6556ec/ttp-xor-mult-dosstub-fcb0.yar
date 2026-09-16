rule TTP_XOR_MULT_DOSStub_fcb0 {
  strings:
    $key_fcb0 = { a8 d8 [2] dc c0 [2] 9b c2 [2] dc d3 [2] 92 df [2] 9e d5 [2] 89 de [2] 92 90 [2] af }

  condition:
    any of them
}