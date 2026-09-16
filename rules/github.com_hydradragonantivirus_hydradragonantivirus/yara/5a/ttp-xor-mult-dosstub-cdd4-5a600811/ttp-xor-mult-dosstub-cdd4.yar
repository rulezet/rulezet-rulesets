rule TTP_XOR_MULT_DOSStub_cdd4 {
  strings:
    $key_cdd4 = { 99 bc [2] ed a4 [2] aa a6 [2] ed b7 [2] a3 bb [2] af b1 [2] b8 ba [2] a3 f4 [2] 9e }

  condition:
    any of them
}