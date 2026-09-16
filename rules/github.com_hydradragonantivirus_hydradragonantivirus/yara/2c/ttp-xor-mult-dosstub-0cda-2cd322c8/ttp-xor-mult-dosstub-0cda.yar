rule TTP_XOR_MULT_DOSStub_0cda {
  strings:
    $key_0cda = { 58 b2 [2] 2c aa [2] 6b a8 [2] 2c b9 [2] 62 b5 [2] 6e bf [2] 79 b4 [2] 62 fa [2] 5f }

  condition:
    any of them
}