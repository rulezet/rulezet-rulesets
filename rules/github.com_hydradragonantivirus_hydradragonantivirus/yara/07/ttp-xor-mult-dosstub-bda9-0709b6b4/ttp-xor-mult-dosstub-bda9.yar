rule TTP_XOR_MULT_DOSStub_bda9 {
  strings:
    $key_bda9 = { e9 c1 [2] 9d d9 [2] da db [2] 9d ca [2] d3 c6 [2] df cc [2] c8 c7 [2] d3 89 [2] ee }

  condition:
    any of them
}