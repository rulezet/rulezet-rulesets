rule TTP_XOR_MULT_DOSStub_fcd0 {
  strings:
    $key_fcd0 = { a8 b8 [2] dc a0 [2] 9b a2 [2] dc b3 [2] 92 bf [2] 9e b5 [2] 89 be [2] 92 f0 [2] af }

  condition:
    any of them
}