rule TTP_XOR_MULT_DOSStub_a9b2 {
  strings:
    $key_a9b2 = { fd da [2] 89 c2 [2] ce c0 [2] 89 d1 [2] c7 dd [2] cb d7 [2] dc dc [2] c7 92 [2] fa }

  condition:
    any of them
}