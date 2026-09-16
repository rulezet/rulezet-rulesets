rule TTP_XOR_MULT_DOSStub_ddd3 {
  strings:
    $key_ddd3 = { 89 bb [2] fd a3 [2] ba a1 [2] fd b0 [2] b3 bc [2] bf b6 [2] a8 bd [2] b3 f3 [2] 8e }

  condition:
    any of them
}