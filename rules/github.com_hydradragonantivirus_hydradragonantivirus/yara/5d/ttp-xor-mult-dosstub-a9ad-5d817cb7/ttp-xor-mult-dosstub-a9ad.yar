rule TTP_XOR_MULT_DOSStub_a9ad {
  strings:
    $key_a9ad = { fd c5 [2] 89 dd [2] ce df [2] 89 ce [2] c7 c2 [2] cb c8 [2] dc c3 [2] c7 8d [2] fa }

  condition:
    any of them
}