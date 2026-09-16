rule TTP_XOR_MULT_DOSStub_8eda {
  strings:
    $key_8eda = { da b2 [2] ae aa [2] e9 a8 [2] ae b9 [2] e0 b5 [2] ec bf [2] fb b4 [2] e0 fa [2] dd }

  condition:
    any of them
}