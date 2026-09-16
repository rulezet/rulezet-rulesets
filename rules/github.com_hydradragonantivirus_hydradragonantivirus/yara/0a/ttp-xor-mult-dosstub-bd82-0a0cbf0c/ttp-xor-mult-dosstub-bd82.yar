rule TTP_XOR_MULT_DOSStub_bd82 {
  strings:
    $key_bd82 = { e9 ea [2] 9d f2 [2] da f0 [2] 9d e1 [2] d3 ed [2] df e7 [2] c8 ec [2] d3 a2 [2] ee }

  condition:
    any of them
}