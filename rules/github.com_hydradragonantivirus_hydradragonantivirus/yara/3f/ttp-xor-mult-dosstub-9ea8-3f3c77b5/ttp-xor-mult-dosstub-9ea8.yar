rule TTP_XOR_MULT_DOSStub_9ea8 {
  strings:
    $key_9ea8 = { ca c0 [2] be d8 [2] f9 da [2] be cb [2] f0 c7 [2] fc cd [2] eb c6 [2] f0 88 [2] cd }

  condition:
    any of them
}