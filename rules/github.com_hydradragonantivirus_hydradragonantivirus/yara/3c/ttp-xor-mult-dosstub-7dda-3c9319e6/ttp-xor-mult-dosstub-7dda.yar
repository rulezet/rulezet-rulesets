rule TTP_XOR_MULT_DOSStub_7dda {
  strings:
    $key_7dda = { 29 b2 [2] 5d aa [2] 1a a8 [2] 5d b9 [2] 13 b5 [2] 1f bf [2] 08 b4 [2] 13 fa [2] 2e }

  condition:
    any of them
}