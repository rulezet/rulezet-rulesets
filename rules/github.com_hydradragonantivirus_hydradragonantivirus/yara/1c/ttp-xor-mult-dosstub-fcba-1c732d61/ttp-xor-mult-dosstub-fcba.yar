rule TTP_XOR_MULT_DOSStub_fcba {
  strings:
    $key_fcba = { a8 d2 [2] dc ca [2] 9b c8 [2] dc d9 [2] 92 d5 [2] 9e df [2] 89 d4 [2] 92 9a [2] af }

  condition:
    any of them
}