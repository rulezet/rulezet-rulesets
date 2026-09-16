rule TTP_XOR_MULT_DOSStub_fcb5 {
  strings:
    $key_fcb5 = { a8 dd [2] dc c5 [2] 9b c7 [2] dc d6 [2] 92 da [2] 9e d0 [2] 89 db [2] 92 95 [2] af }

  condition:
    any of them
}