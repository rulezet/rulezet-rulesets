rule TTP_XOR_MULT_DOSStub_cdd2 {
  strings:
    $key_cdd2 = { 99 ba [2] ed a2 [2] aa a0 [2] ed b1 [2] a3 bd [2] af b7 [2] b8 bc [2] a3 f2 [2] 9e }

  condition:
    any of them
}