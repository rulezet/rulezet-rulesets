rule TTP_XOR_MULT_DOSStub_d9da {
  strings:
    $key_d9da = { 8d b2 [2] f9 aa [2] be a8 [2] f9 b9 [2] b7 b5 [2] bb bf [2] ac b4 [2] b7 fa [2] 8a }

  condition:
    any of them
}