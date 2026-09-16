rule TTP_XOR_MULT_DOSStub_a9bf {
  strings:
    $key_a9bf = { fd d7 [2] 89 cf [2] ce cd [2] 89 dc [2] c7 d0 [2] cb da [2] dc d1 [2] c7 9f [2] fa }

  condition:
    any of them
}