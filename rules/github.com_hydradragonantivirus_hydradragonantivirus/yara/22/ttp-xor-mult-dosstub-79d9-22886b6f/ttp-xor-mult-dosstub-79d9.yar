rule TTP_XOR_MULT_DOSStub_79d9 {
  strings:
    $key_79d9 = { 2d b1 [2] 59 a9 [2] 1e ab [2] 59 ba [2] 17 b6 [2] 1b bc [2] 0c b7 [2] 17 f9 [2] 2a }

  condition:
    any of them
}