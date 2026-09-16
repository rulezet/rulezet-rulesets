rule TTP_XOR_MULT_DOSStub_a998 {
  strings:
    $key_a998 = { fd f0 [2] 89 e8 [2] ce ea [2] 89 fb [2] c7 f7 [2] cb fd [2] dc f6 [2] c7 b8 [2] fa }

  condition:
    any of them
}