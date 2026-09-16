rule TTP_XOR_MULT_DOSStub_1cda {
  strings:
    $key_1cda = { 48 b2 [2] 3c aa [2] 7b a8 [2] 3c b9 [2] 72 b5 [2] 7e bf [2] 69 b4 [2] 72 fa [2] 4f }

  condition:
    any of them
}