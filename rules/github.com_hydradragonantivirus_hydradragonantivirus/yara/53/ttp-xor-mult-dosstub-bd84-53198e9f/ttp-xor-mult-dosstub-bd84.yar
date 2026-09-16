rule TTP_XOR_MULT_DOSStub_bd84 {
  strings:
    $key_bd84 = { e9 ec [2] 9d f4 [2] da f6 [2] 9d e7 [2] d3 eb [2] df e1 [2] c8 ea [2] d3 a4 [2] ee }

  condition:
    any of them
}