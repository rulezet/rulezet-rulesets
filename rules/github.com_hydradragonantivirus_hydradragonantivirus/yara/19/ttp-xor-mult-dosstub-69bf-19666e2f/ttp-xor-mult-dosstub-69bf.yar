rule TTP_XOR_MULT_DOSStub_69bf {
  strings:
    $key_69bf = { 3d d7 [2] 49 cf [2] 0e cd [2] 49 dc [2] 07 d0 [2] 0b da [2] 1c d1 [2] 07 9f [2] 3a }

  condition:
    any of them
}