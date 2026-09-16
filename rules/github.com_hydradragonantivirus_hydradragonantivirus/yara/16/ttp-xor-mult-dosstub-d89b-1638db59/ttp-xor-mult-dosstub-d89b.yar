rule TTP_XOR_MULT_DOSStub_d89b {
  strings:
    $key_d89b = { 8c f3 [2] f8 eb [2] bf e9 [2] f8 f8 [2] b6 f4 [2] ba fe [2] ad f5 [2] b6 bb [2] 8b }

  condition:
    any of them
}