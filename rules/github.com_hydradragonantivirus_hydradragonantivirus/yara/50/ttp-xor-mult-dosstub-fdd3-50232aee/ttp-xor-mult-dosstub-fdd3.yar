rule TTP_XOR_MULT_DOSStub_fdd3 {
  strings:
    $key_fdd3 = { a9 bb [2] dd a3 [2] 9a a1 [2] dd b0 [2] 93 bc [2] 9f b6 [2] 88 bd [2] 93 f3 [2] ae }

  condition:
    any of them
}