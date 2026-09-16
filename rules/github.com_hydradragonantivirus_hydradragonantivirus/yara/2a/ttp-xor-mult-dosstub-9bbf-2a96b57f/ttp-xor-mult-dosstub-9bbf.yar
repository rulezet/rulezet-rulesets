rule TTP_XOR_MULT_DOSStub_9bbf {
  strings:
    $key_9bbf = { cf d7 [2] bb cf [2] fc cd [2] bb dc [2] f5 d0 [2] f9 da [2] ee d1 [2] f5 9f [2] c8 }

  condition:
    any of them
}