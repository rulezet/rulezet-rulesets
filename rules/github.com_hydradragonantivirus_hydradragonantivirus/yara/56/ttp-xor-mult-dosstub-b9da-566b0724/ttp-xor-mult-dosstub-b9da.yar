rule TTP_XOR_MULT_DOSStub_b9da {
  strings:
    $key_b9da = { ed b2 [2] 99 aa [2] de a8 [2] 99 b9 [2] d7 b5 [2] db bf [2] cc b4 [2] d7 fa [2] ea }

  condition:
    any of them
}