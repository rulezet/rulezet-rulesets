rule TTP_XOR_MULT_DOSStub_3eda {
  strings:
    $key_3eda = { 6a b2 [2] 1e aa [2] 59 a8 [2] 1e b9 [2] 50 b5 [2] 5c bf [2] 4b b4 [2] 50 fa [2] 6d }

  condition:
    any of them
}