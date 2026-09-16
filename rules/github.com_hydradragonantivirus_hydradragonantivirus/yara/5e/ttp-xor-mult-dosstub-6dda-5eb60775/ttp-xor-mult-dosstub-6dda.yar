rule TTP_XOR_MULT_DOSStub_6dda {
  strings:
    $key_6dda = { 39 b2 [2] 4d aa [2] 0a a8 [2] 4d b9 [2] 03 b5 [2] 0f bf [2] 18 b4 [2] 03 fa [2] 3e }

  condition:
    any of them
}