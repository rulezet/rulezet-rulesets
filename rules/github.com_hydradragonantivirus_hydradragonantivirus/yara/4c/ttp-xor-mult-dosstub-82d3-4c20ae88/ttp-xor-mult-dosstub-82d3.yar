rule TTP_XOR_MULT_DOSStub_82d3 {
  strings:
    $key_82d3 = { d6 bb [2] a2 a3 [2] e5 a1 [2] a2 b0 [2] ec bc [2] e0 b6 [2] f7 bd [2] ec f3 [2] d1 }

  condition:
    any of them
}