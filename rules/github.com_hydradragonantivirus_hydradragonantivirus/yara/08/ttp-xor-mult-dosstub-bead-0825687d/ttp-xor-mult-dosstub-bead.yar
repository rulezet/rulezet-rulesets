rule TTP_XOR_MULT_DOSStub_bead {
  strings:
    $key_bead = { ea c5 [2] 9e dd [2] d9 df [2] 9e ce [2] d0 c2 [2] dc c8 [2] cb c3 [2] d0 8d [2] ed }

  condition:
    any of them
}