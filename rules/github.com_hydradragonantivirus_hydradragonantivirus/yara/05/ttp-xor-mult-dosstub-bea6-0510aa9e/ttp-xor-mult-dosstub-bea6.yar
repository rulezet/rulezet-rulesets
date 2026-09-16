rule TTP_XOR_MULT_DOSStub_bea6 {
  strings:
    $key_bea6 = { ea ce [2] 9e d6 [2] d9 d4 [2] 9e c5 [2] d0 c9 [2] dc c3 [2] cb c8 [2] d0 86 [2] ed }

  condition:
    any of them
}