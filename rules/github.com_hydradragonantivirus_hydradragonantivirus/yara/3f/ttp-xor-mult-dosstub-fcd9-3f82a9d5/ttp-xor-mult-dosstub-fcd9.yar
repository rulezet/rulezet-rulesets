rule TTP_XOR_MULT_DOSStub_fcd9 {
  strings:
    $key_fcd9 = { a8 b1 [2] dc a9 [2] 9b ab [2] dc ba [2] 92 b6 [2] 9e bc [2] 89 b7 [2] 92 f9 [2] af }

  condition:
    any of them
}