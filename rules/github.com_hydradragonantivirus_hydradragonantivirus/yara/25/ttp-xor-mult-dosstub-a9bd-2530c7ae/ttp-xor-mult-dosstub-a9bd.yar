rule TTP_XOR_MULT_DOSStub_a9bd {
  strings:
    $key_a9bd = { fd d5 [2] 89 cd [2] ce cf [2] 89 de [2] c7 d2 [2] cb d8 [2] dc d3 [2] c7 9d [2] fa }

  condition:
    any of them
}