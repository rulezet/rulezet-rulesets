rule TTP_XOR_MULT_DOSStub_08d9 {
  strings:
    $key_08d9 = { 5c b1 [2] 28 a9 [2] 6f ab [2] 28 ba [2] 66 b6 [2] 6a bc [2] 7d b7 [2] 66 f9 [2] 5b }

  condition:
    any of them
}