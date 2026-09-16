rule TTP_XOR_MULT_DOSStub_a9a8 {
  strings:
    $key_a9a8 = { fd c0 [2] 89 d8 [2] ce da [2] 89 cb [2] c7 c7 [2] cb cd [2] dc c6 [2] c7 88 [2] fa }

  condition:
    any of them
}