rule TTP_XOR_MULT_DOSStub_bdb6 {
  strings:
    $key_bdb6 = { e9 de [2] 9d c6 [2] da c4 [2] 9d d5 [2] d3 d9 [2] df d3 [2] c8 d8 [2] d3 96 [2] ee }

  condition:
    any of them
}