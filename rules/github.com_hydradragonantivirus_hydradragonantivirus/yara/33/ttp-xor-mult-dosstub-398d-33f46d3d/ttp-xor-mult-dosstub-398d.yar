rule TTP_XOR_MULT_DOSStub_398d {
  strings:
    $key_398d = { 6d e5 [2] 19 fd [2] 5e ff [2] 19 ee [2] 57 e2 [2] 5b e8 [2] 4c e3 [2] 57 ad [2] 6a }

  condition:
    any of them
}