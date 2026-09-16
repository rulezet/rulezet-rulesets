rule TTP_XOR_MULT_DOSStub_a5fe {
  strings:
    $key_a5fe = { f1 96 [2] 85 8e [2] c2 8c [2] 85 9d [2] cb 91 [2] c7 9b [2] d0 90 [2] cb de [2] f6 }

  condition:
    any of them
}