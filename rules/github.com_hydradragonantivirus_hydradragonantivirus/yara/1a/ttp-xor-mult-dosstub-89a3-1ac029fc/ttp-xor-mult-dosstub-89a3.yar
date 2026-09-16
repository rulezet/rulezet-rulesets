rule TTP_XOR_MULT_DOSStub_89a3 {
  strings:
    $key_89a3 = { dd cb [2] a9 d3 [2] ee d1 [2] a9 c0 [2] e7 cc [2] eb c6 [2] fc cd [2] e7 83 [2] da }

  condition:
    any of them
}