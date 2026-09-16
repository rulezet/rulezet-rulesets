rule TTP_XOR_MULT_DOSStub_fcc3 {
  strings:
    $key_fcc3 = { a8 ab [2] dc b3 [2] 9b b1 [2] dc a0 [2] 92 ac [2] 9e a6 [2] 89 ad [2] 92 e3 [2] af }

  condition:
    any of them
}