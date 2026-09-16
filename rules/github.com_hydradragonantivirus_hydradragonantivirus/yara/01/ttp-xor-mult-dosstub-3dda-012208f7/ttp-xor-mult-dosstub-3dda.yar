rule TTP_XOR_MULT_DOSStub_3dda {
  strings:
    $key_3dda = { 69 b2 [2] 1d aa [2] 5a a8 [2] 1d b9 [2] 53 b5 [2] 5f bf [2] 48 b4 [2] 53 fa [2] 6e }

  condition:
    any of them
}