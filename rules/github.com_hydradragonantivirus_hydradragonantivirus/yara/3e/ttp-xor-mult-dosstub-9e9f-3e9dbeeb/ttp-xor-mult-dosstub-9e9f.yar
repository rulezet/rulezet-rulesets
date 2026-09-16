rule TTP_XOR_MULT_DOSStub_9e9f {
  strings:
    $key_9e9f = { ca f7 [2] be ef [2] f9 ed [2] be fc [2] f0 f0 [2] fc fa [2] eb f1 [2] f0 bf [2] cd }

  condition:
    any of them
}