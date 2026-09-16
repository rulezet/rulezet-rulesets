rule TTP_XOR_MULT_DOSStub_fcc5 {
  strings:
    $key_fcc5 = { a8 ad [2] dc b5 [2] 9b b7 [2] dc a6 [2] 92 aa [2] 9e a0 [2] 89 ab [2] 92 e5 [2] af }

  condition:
    any of them
}