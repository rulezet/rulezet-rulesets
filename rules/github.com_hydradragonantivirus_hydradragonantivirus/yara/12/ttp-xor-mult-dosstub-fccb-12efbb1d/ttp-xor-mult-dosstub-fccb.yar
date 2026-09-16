rule TTP_XOR_MULT_DOSStub_fccb {
  strings:
    $key_fccb = { a8 a3 [2] dc bb [2] 9b b9 [2] dc a8 [2] 92 a4 [2] 9e ae [2] 89 a5 [2] 92 eb [2] af }

  condition:
    any of them
}