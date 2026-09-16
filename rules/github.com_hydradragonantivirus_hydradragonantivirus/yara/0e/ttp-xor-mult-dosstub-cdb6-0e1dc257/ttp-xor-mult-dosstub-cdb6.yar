rule TTP_XOR_MULT_DOSStub_cdb6 {
  strings:
    $key_cdb6 = { 99 de [2] ed c6 [2] aa c4 [2] ed d5 [2] a3 d9 [2] af d3 [2] b8 d8 [2] a3 96 [2] 9e }

  condition:
    any of them
}