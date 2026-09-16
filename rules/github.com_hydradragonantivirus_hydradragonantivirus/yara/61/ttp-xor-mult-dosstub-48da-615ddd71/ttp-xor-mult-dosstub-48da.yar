rule TTP_XOR_MULT_DOSStub_48da {
  strings:
    $key_48da = { 1c b2 [2] 68 aa [2] 2f a8 [2] 68 b9 [2] 26 b5 [2] 2a bf [2] 3d b4 [2] 26 fa [2] 1b }

  condition:
    any of them
}