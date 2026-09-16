rule TTP_XOR_MULT_DOSStub_9e99 {
  strings:
    $key_9e99 = { ca f1 [2] be e9 [2] f9 eb [2] be fa [2] f0 f6 [2] fc fc [2] eb f7 [2] f0 b9 [2] cd }

  condition:
    any of them
}