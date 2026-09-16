rule TTP_XOR_MULT_DOSStub_6eca {
  strings:
    $key_6eca = { 3a a2 [2] 4e ba [2] 09 b8 [2] 4e a9 [2] 00 a5 [2] 0c af [2] 1b a4 [2] 00 ea [2] 3d }

  condition:
    any of them
}