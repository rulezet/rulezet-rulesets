rule TTP_XOR_MULT_DOSStub_fcca {
  strings:
    $key_fcca = { a8 a2 [2] dc ba [2] 9b b8 [2] dc a9 [2] 92 a5 [2] 9e af [2] 89 a4 [2] 92 ea [2] af }

  condition:
    any of them
}