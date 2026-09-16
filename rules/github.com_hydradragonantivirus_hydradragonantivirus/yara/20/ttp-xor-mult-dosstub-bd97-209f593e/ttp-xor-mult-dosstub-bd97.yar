rule TTP_XOR_MULT_DOSStub_bd97 {
  strings:
    $key_bd97 = { e9 ff [2] 9d e7 [2] da e5 [2] 9d f4 [2] d3 f8 [2] df f2 [2] c8 f9 [2] d3 b7 [2] ee }

  condition:
    any of them
}