rule TTP_XOR_MULT_DOSStub_78da {
  strings:
    $key_78da = { 2c b2 [2] 58 aa [2] 1f a8 [2] 58 b9 [2] 16 b5 [2] 1a bf [2] 0d b4 [2] 16 fa [2] 2b }

  condition:
    any of them
}