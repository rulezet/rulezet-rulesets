rule TTP_XOR_MULT_DOSStub_58da {
  strings:
    $key_58da = { 0c b2 [2] 78 aa [2] 3f a8 [2] 78 b9 [2] 36 b5 [2] 3a bf [2] 2d b4 [2] 36 fa [2] 0b }

  condition:
    any of them
}