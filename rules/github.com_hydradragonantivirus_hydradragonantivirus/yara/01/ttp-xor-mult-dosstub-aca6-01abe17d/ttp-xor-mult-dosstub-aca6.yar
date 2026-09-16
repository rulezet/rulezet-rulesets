rule TTP_XOR_MULT_DOSStub_aca6 {
  strings:
    $key_aca6 = { f8 ce [2] 8c d6 [2] cb d4 [2] 8c c5 [2] c2 c9 [2] ce c3 [2] d9 c8 [2] c2 86 [2] ff }

  condition:
    any of them
}