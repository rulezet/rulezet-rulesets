rule TTP_XOR_MULT_DOSStub_fcb7 {
  strings:
    $key_fcb7 = { a8 df [2] dc c7 [2] 9b c5 [2] dc d4 [2] 92 d8 [2] 9e d2 [2] 89 d9 [2] 92 97 [2] af }

  condition:
    any of them
}