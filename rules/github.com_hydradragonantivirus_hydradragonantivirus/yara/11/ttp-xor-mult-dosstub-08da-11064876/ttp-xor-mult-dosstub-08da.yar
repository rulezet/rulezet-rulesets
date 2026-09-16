rule TTP_XOR_MULT_DOSStub_08da {
  strings:
    $key_08da = { 5c b2 [2] 28 aa [2] 6f a8 [2] 28 b9 [2] 66 b5 [2] 6a bf [2] 7d b4 [2] 66 fa [2] 5b }

  condition:
    any of them
}