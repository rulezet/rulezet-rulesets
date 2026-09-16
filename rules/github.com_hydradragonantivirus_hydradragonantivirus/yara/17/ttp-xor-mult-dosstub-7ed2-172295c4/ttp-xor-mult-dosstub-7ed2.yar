rule TTP_XOR_MULT_DOSStub_7ed2 {
  strings:
    $key_7ed2 = { 2a ba [2] 5e a2 [2] 19 a0 [2] 5e b1 [2] 10 bd [2] 1c b7 [2] 0b bc [2] 10 f2 [2] 2d }

  condition:
    any of them
}