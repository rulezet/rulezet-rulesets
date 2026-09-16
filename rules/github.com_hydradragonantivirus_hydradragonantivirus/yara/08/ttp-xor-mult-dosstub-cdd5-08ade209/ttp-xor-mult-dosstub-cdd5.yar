rule TTP_XOR_MULT_DOSStub_cdd5 {
  strings:
    $key_cdd5 = { 99 bd [2] ed a5 [2] aa a7 [2] ed b6 [2] a3 ba [2] af b0 [2] b8 bb [2] a3 f5 [2] 9e }

  condition:
    any of them
}