rule TTP_XOR_MULT_DOSStub_fc8c {
  strings:
    $key_fc8c = { a8 e4 [2] dc fc [2] 9b fe [2] dc ef [2] 92 e3 [2] 9e e9 [2] 89 e2 [2] 92 ac [2] af }

  condition:
    any of them
}