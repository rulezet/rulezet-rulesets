rule TTP_XOR_MULT_DOSStub_fcd8 {
  strings:
    $key_fcd8 = { a8 b0 [2] dc a8 [2] 9b aa [2] dc bb [2] 92 b7 [2] 9e bd [2] 89 b6 [2] 92 f8 [2] af }

  condition:
    any of them
}