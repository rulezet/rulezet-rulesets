rule TTP_XOR_MULT_DOSStub_9e8a {
  strings:
    $key_9e8a = { ca e2 [2] be fa [2] f9 f8 [2] be e9 [2] f0 e5 [2] fc ef [2] eb e4 [2] f0 aa [2] cd }

  condition:
    any of them
}