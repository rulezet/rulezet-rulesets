rule TTP_XOR_MULT_DOSStub_acab {
  strings:
    $key_acab = { f8 c3 [2] 8c db [2] cb d9 [2] 8c c8 [2] c2 c4 [2] ce ce [2] d9 c5 [2] c2 8b [2] ff }

  condition:
    any of them
}