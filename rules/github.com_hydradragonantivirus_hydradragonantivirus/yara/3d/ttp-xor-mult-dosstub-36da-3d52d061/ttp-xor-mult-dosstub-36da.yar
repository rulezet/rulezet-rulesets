rule TTP_XOR_MULT_DOSStub_36da {
  strings:
    $key_36da = { 62 b2 [2] 16 aa [2] 51 a8 [2] 16 b9 [2] 58 b5 [2] 54 bf [2] 43 b4 [2] 58 fa [2] 65 }

  condition:
    any of them
}