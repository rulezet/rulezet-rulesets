rule TTP_XOR_MULT_DOSStub_bdb0 {
  strings:
    $key_bdb0 = { e9 d8 [2] 9d c0 [2] da c2 [2] 9d d3 [2] d3 df [2] df d5 [2] c8 de [2] d3 90 [2] ee }

  condition:
    any of them
}