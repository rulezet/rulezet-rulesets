rule TTP_XOR_MULT_DOSStub_19bf {
  strings:
    $key_19bf = { 4d d7 [2] 39 cf [2] 7e cd [2] 39 dc [2] 77 d0 [2] 7b da [2] 6c d1 [2] 77 9f [2] 4a }

  condition:
    any of them
}