rule TTP_XOR_MULT_DOSStub_49bf {
  strings:
    $key_49bf = { 1d d7 [2] 69 cf [2] 2e cd [2] 69 dc [2] 27 d0 [2] 2b da [2] 3c d1 [2] 27 9f [2] 1a }

  condition:
    any of them
}