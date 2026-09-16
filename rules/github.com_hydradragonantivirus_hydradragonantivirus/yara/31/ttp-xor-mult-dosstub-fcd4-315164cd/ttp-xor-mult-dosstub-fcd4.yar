rule TTP_XOR_MULT_DOSStub_fcd4 {
  strings:
    $key_fcd4 = { a8 bc [2] dc a4 [2] 9b a6 [2] dc b7 [2] 92 bb [2] 9e b1 [2] 89 ba [2] 92 f4 [2] af }

  condition:
    any of them
}