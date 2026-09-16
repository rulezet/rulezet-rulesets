rule TTP_XOR_MULT_DOSStub_bdb2 {
  strings:
    $key_bdb2 = { e9 da [2] 9d c2 [2] da c0 [2] 9d d1 [2] d3 dd [2] df d7 [2] c8 dc [2] d3 92 [2] ee }

  condition:
    any of them
}