rule TTP_XOR_MULT_DOSStub_38da {
  strings:
    $key_38da = { 6c b2 [2] 18 aa [2] 5f a8 [2] 18 b9 [2] 56 b5 [2] 5a bf [2] 4d b4 [2] 56 fa [2] 6b }

  condition:
    any of them
}