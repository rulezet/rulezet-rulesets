rule TTP_XOR_MULT_DOSStub_cdd6 {
  strings:
    $key_cdd6 = { 99 be [2] ed a6 [2] aa a4 [2] ed b5 [2] a3 b9 [2] af b3 [2] b8 b8 [2] a3 f6 [2] 9e }

  condition:
    any of them
}