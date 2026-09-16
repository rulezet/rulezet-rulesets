rule TTP_XOR_MULT_DOSStub_fdd5 {
  strings:
    $key_fdd5 = { a9 bd [2] dd a5 [2] 9a a7 [2] dd b6 [2] 93 ba [2] 9f b0 [2] 88 bb [2] 93 f5 [2] ae }

  condition:
    any of them
}