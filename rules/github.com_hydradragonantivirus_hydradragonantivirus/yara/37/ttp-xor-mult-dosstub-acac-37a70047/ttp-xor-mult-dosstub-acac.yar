rule TTP_XOR_MULT_DOSStub_acac {
  strings:
    $key_acac = { f8 c4 [2] 8c dc [2] cb de [2] 8c cf [2] c2 c3 [2] ce c9 [2] d9 c2 [2] c2 8c [2] ff }

  condition:
    any of them
}