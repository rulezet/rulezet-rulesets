rule TTP_XOR_MULT_DOSStub_bdd5 {
  strings:
    $key_bdd5 = { e9 bd [2] 9d a5 [2] da a7 [2] 9d b6 [2] d3 ba [2] df b0 [2] c8 bb [2] d3 f5 [2] ee }

  condition:
    any of them
}