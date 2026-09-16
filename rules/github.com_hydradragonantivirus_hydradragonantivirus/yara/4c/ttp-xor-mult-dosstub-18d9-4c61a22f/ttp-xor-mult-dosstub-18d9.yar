rule TTP_XOR_MULT_DOSStub_18d9 {
  strings:
    $key_18d9 = { 4c b1 [2] 38 a9 [2] 7f ab [2] 38 ba [2] 76 b6 [2] 7a bc [2] 6d b7 [2] 76 f9 [2] 4b }

  condition:
    any of them
}