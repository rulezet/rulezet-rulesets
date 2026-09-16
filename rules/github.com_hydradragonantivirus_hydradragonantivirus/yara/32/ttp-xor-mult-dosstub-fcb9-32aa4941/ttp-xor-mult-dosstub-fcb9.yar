rule TTP_XOR_MULT_DOSStub_fcb9 {
  strings:
    $key_fcb9 = { a8 d1 [2] dc c9 [2] 9b cb [2] dc da [2] 92 d6 [2] 9e dc [2] 89 d7 [2] 92 99 [2] af }

  condition:
    any of them
}