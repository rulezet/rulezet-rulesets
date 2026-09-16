rule TTP_XOR_MULT_DOSStub_9e9b {
  strings:
    $key_9e9b = { ca f3 [2] be eb [2] f9 e9 [2] be f8 [2] f0 f4 [2] fc fe [2] eb f5 [2] f0 bb [2] cd }

  condition:
    any of them
}