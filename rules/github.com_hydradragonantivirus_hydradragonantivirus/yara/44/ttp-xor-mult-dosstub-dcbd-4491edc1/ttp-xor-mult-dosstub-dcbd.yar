rule TTP_XOR_MULT_DOSStub_dcbd {
  strings:
    $key_dcbd = { 88 d5 [2] fc cd [2] bb cf [2] fc de [2] b2 d2 [2] be d8 [2] a9 d3 [2] b2 9d [2] 8f }

  condition:
    any of them
}