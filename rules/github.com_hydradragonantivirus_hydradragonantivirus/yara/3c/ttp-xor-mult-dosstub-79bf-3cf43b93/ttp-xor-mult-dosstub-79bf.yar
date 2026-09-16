rule TTP_XOR_MULT_DOSStub_79bf {
  strings:
    $key_79bf = { 2d d7 [2] 59 cf [2] 1e cd [2] 59 dc [2] 17 d0 [2] 1b da [2] 0c d1 [2] 17 9f [2] 2a }

  condition:
    any of them
}