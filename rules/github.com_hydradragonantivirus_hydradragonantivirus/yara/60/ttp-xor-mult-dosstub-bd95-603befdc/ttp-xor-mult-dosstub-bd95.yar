rule TTP_XOR_MULT_DOSStub_bd95 {
  strings:
    $key_bd95 = { e9 fd [2] 9d e5 [2] da e7 [2] 9d f6 [2] d3 fa [2] df f0 [2] c8 fb [2] d3 b5 [2] ee }

  condition:
    any of them
}