rule TTP_XOR_MULT_DOSStub_80fe {
  strings:
    $key_80fe = { d4 96 [2] a0 8e [2] e7 8c [2] a0 9d [2] ee 91 [2] e2 9b [2] f5 90 [2] ee de [2] d3 }

  condition:
    any of them
}