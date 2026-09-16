rule TTP_XOR_MULT_DOSStub_9e8e {
  strings:
    $key_9e8e = { ca e6 [2] be fe [2] f9 fc [2] be ed [2] f0 e1 [2] fc eb [2] eb e0 [2] f0 ae [2] cd }

  condition:
    any of them
}