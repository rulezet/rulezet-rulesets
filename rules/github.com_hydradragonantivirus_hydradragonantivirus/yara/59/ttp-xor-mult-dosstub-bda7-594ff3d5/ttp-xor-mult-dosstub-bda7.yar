rule TTP_XOR_MULT_DOSStub_bda7 {
  strings:
    $key_bda7 = { e9 cf [2] 9d d7 [2] da d5 [2] 9d c4 [2] d3 c8 [2] df c2 [2] c8 c9 [2] d3 87 [2] ee }

  condition:
    any of them
}