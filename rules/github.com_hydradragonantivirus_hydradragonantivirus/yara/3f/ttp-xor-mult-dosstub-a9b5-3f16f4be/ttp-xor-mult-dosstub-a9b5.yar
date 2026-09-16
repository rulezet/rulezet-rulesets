rule TTP_XOR_MULT_DOSStub_a9b5 {
  strings:
    $key_a9b5 = { fd dd [2] 89 c5 [2] ce c7 [2] 89 d6 [2] c7 da [2] cb d0 [2] dc db [2] c7 95 [2] fa }

  condition:
    any of them
}