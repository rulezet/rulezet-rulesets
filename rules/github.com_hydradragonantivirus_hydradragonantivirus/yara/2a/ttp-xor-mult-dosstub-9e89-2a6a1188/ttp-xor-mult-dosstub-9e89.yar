rule TTP_XOR_MULT_DOSStub_9e89 {
  strings:
    $key_9e89 = { ca e1 [2] be f9 [2] f9 fb [2] be ea [2] f0 e6 [2] fc ec [2] eb e7 [2] f0 a9 [2] cd }

  condition:
    any of them
}