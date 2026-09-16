rule TTP_XOR_MULT_DOSStub_bd9d {
  strings:
    $key_bd9d = { e9 f5 [2] 9d ed [2] da ef [2] 9d fe [2] d3 f2 [2] df f8 [2] c8 f3 [2] d3 bd [2] ee }

  condition:
    any of them
}