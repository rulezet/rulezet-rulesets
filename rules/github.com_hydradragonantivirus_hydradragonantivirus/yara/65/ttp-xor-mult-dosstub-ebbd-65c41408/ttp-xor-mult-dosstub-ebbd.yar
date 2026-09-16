rule TTP_XOR_MULT_DOSStub_ebbd {
  strings:
    $key_ebbd = { bf d5 [2] cb cd [2] 8c cf [2] cb de [2] 85 d2 [2] 89 d8 [2] 9e d3 [2] 85 9d [2] b8 }

  condition:
    any of them
}