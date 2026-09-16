rule TTP_XOR_MULT_DOSStub_cdd0 {
  strings:
    $key_cdd0 = { 99 b8 [2] ed a0 [2] aa a2 [2] ed b3 [2] a3 bf [2] af b5 [2] b8 be [2] a3 f0 [2] 9e }

  condition:
    any of them
}