rule TTP_XOR_MULT_DOSStub_1dda {
  strings:
    $key_1dda = { 49 b2 [2] 3d aa [2] 7a a8 [2] 3d b9 [2] 73 b5 [2] 7f bf [2] 68 b4 [2] 73 fa [2] 4e }

  condition:
    any of them
}