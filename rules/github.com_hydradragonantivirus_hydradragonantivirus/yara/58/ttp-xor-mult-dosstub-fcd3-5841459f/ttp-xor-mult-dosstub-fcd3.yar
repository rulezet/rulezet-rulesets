rule TTP_XOR_MULT_DOSStub_fcd3 {
  strings:
    $key_fcd3 = { a8 bb [2] dc a3 [2] 9b a1 [2] dc b0 [2] 92 bc [2] 9e b6 [2] 89 bd [2] 92 f3 [2] af }

  condition:
    any of them
}