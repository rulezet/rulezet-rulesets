rule TTP_XOR_MULT_DOSStub_5eda {
  strings:
    $key_5eda = { 0a b2 [2] 7e aa [2] 39 a8 [2] 7e b9 [2] 30 b5 [2] 3c bf [2] 2b b4 [2] 30 fa [2] 0d }

  condition:
    any of them
}