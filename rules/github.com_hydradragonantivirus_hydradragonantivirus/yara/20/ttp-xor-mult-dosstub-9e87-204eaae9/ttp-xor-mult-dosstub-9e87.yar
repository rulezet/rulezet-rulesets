rule TTP_XOR_MULT_DOSStub_9e87 {
  strings:
    $key_9e87 = { ca ef [2] be f7 [2] f9 f5 [2] be e4 [2] f0 e8 [2] fc e2 [2] eb e9 [2] f0 a7 [2] cd }

  condition:
    any of them
}