rule TTP_XOR_MULT_DOSStub_09bf {
  strings:
    $key_09bf = { 5d d7 [2] 29 cf [2] 6e cd [2] 29 dc [2] 67 d0 [2] 6b da [2] 7c d1 [2] 67 9f [2] 5a }

  condition:
    any of them
}