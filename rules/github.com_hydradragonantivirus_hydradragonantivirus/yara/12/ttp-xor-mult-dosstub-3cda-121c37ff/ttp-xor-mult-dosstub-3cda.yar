rule TTP_XOR_MULT_DOSStub_3cda {
  strings:
    $key_3cda = { 68 b2 [2] 1c aa [2] 5b a8 [2] 1c b9 [2] 52 b5 [2] 5e bf [2] 49 b4 [2] 52 fa [2] 6f }

  condition:
    any of them
}