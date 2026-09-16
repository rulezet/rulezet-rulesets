rule TTP_XOR_MULT_DOSStub_9e88 {
  strings:
    $key_9e88 = { ca e0 [2] be f8 [2] f9 fa [2] be eb [2] f0 e7 [2] fc ed [2] eb e6 [2] f0 a8 [2] cd }

  condition:
    any of them
}