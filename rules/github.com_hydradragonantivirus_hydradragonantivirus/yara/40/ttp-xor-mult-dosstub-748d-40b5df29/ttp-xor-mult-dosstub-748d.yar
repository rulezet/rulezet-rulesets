rule TTP_XOR_MULT_DOSStub_748d {
  strings:
    $key_748d = { 20 e5 [2] 54 fd [2] 13 ff [2] 54 ee [2] 1a e2 [2] 16 e8 [2] 01 e3 [2] 1a ad [2] 27 }

  condition:
    any of them
}