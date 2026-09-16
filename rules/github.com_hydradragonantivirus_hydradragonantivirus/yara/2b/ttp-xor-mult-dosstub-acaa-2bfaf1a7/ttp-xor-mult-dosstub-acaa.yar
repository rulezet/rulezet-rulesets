rule TTP_XOR_MULT_DOSStub_acaa {
  strings:
    $key_acaa = { f8 c2 [2] 8c da [2] cb d8 [2] 8c c9 [2] c2 c5 [2] ce cf [2] d9 c4 [2] c2 8a [2] ff }

  condition:
    any of them
}