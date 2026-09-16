rule TTP_XOR_MULT_DOSStub_49da {
  strings:
    $key_49da = { 1d b2 [2] 69 aa [2] 2e a8 [2] 69 b9 [2] 27 b5 [2] 2b bf [2] 3c b4 [2] 27 fa [2] 1a }

  condition:
    any of them
}