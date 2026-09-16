rule TTP_XOR_MULT_DOSStub_9fb6 {
  strings:
    $key_9fb6 = { cb de [2] bf c6 [2] f8 c4 [2] bf d5 [2] f1 d9 [2] fd d3 [2] ea d8 [2] f1 96 [2] cc }

  condition:
    any of them
}