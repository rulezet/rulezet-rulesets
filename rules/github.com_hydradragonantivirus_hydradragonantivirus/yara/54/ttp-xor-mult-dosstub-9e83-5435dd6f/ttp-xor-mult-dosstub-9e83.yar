rule TTP_XOR_MULT_DOSStub_9e83 {
  strings:
    $key_9e83 = { ca eb [2] be f3 [2] f9 f1 [2] be e0 [2] f0 ec [2] fc e6 [2] eb ed [2] f0 a3 [2] cd }

  condition:
    any of them
}