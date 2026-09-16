rule TTP_XOR_MULT_DOSStub_bd8b {
  strings:
    $key_bd8b = { e9 e3 [2] 9d fb [2] da f9 [2] 9d e8 [2] d3 e4 [2] df ee [2] c8 e5 [2] d3 ab [2] ee }

  condition:
    any of them
}