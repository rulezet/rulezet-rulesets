rule TTP_XOR_MULT_DOSStub_bea4 {
  strings:
    $key_bea4 = { ea cc [2] 9e d4 [2] d9 d6 [2] 9e c7 [2] d0 cb [2] dc c1 [2] cb ca [2] d0 84 [2] ed }

  condition:
    any of them
}