rule TTP_XOR_MULT_DOSStub_e9da {
  strings:
    $key_e9da = { bd b2 [2] c9 aa [2] 8e a8 [2] c9 b9 [2] 87 b5 [2] 8b bf [2] 9c b4 [2] 87 fa [2] ba }

  condition:
    any of them
}