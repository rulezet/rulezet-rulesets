rule TTP_XOR_MULT_DOSStub_bdd2 {
  strings:
    $key_bdd2 = { e9 ba [2] 9d a2 [2] da a0 [2] 9d b1 [2] d3 bd [2] df b7 [2] c8 bc [2] d3 f2 [2] ee }

  condition:
    any of them
}