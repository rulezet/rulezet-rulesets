rule TTP_XOR_MULT_DOSStub_a9aa {
  strings:
    $key_a9aa = { fd c2 [2] 89 da [2] ce d8 [2] 89 c9 [2] c7 c5 [2] cb cf [2] dc c4 [2] c7 8a [2] fa }

  condition:
    any of them
}