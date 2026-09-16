rule TTP_XOR_MULT_DOSStub_9ee3 {
  strings:
    $key_9ee3 = { ca 8b [2] be 93 [2] f9 91 [2] be 80 [2] f0 8c [2] fc 86 [2] eb 8d [2] f0 c3 [2] cd }

  condition:
    any of them
}