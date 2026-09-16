rule TTP_XOR_MULT_DOSStub_bdca {
  strings:
    $key_bdca = { e9 a2 [2] 9d ba [2] da b8 [2] 9d a9 [2] d3 a5 [2] df af [2] c8 a4 [2] d3 ea [2] ee }

  condition:
    any of them
}