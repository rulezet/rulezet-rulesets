rule TTP_XOR_MULT_DOSStub_bea7 {
  strings:
    $key_bea7 = { ea cf [2] 9e d7 [2] d9 d5 [2] 9e c4 [2] d0 c8 [2] dc c2 [2] cb c9 [2] d0 87 [2] ed }

  condition:
    any of them
}