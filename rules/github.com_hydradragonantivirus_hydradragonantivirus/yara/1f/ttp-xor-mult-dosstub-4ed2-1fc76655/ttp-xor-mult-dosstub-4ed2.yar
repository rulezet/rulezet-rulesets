rule TTP_XOR_MULT_DOSStub_4ed2 {
  strings:
    $key_4ed2 = { 1a ba [2] 6e a2 [2] 29 a0 [2] 6e b1 [2] 20 bd [2] 2c b7 [2] 3b bc [2] 20 f2 [2] 1d }

  condition:
    any of them
}