rule TTP_XOR_MULT_DOSStub_9e9e {
  strings:
    $key_9e9e = { ca f6 [2] be ee [2] f9 ec [2] be fd [2] f0 f1 [2] fc fb [2] eb f0 [2] f0 be [2] cd }

  condition:
    any of them
}