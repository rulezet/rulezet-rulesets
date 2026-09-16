rule TTP_XOR_MULT_DOSStub_c8da {
  strings:
    $key_c8da = { 9c b2 [2] e8 aa [2] af a8 [2] e8 b9 [2] a6 b5 [2] aa bf [2] bd b4 [2] a6 fa [2] 9b }

  condition:
    any of them
}