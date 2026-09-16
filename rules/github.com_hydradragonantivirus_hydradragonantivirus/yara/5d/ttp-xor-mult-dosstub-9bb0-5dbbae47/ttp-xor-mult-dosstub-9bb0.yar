rule TTP_XOR_MULT_DOSStub_9bb0 {
  strings:
    $key_9bb0 = { cf d8 [2] bb c0 [2] fc c2 [2] bb d3 [2] f5 df [2] f9 d5 [2] ee de [2] f5 90 [2] c8 }

  condition:
    any of them
}