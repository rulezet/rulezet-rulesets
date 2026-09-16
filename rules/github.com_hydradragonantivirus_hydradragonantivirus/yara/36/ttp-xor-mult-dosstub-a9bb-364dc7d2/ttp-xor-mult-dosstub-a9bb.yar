rule TTP_XOR_MULT_DOSStub_a9bb {
  strings:
    $key_a9bb = { fd d3 [2] 89 cb [2] ce c9 [2] 89 d8 [2] c7 d4 [2] cb de [2] dc d5 [2] c7 9b [2] fa }

  condition:
    any of them
}