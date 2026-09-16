rule TTP_XOR_MULT_DOSStub_aca0 {
  strings:
    $key_aca0 = { f8 c8 [2] 8c d0 [2] cb d2 [2] 8c c3 [2] c2 cf [2] ce c5 [2] d9 ce [2] c2 80 [2] ff }

  condition:
    any of them
}