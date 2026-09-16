rule TTP_XOR_MULT_DOSStub_44da {
  strings:
    $key_44da = { 10 b2 [2] 64 aa [2] 23 a8 [2] 64 b9 [2] 2a b5 [2] 26 bf [2] 31 b4 [2] 2a fa [2] 17 }

  condition:
    any of them
}