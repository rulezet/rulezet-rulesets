rule TTP_XOR_MULT_DOSStub_bea0 {
  strings:
    $key_bea0 = { ea c8 [2] 9e d0 [2] d9 d2 [2] 9e c3 [2] d0 cf [2] dc c5 [2] cb ce [2] d0 80 [2] ed }

  condition:
    any of them
}