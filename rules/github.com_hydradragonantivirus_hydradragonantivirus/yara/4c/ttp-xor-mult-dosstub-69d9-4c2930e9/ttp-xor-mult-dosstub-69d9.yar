rule TTP_XOR_MULT_DOSStub_69d9 {
  strings:
    $key_69d9 = { 3d b1 [2] 49 a9 [2] 0e ab [2] 49 ba [2] 07 b6 [2] 0b bc [2] 1c b7 [2] 07 f9 [2] 3a }

  condition:
    any of them
}