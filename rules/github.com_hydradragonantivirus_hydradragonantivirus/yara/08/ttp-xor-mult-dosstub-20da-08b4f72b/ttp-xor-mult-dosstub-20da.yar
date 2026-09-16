rule TTP_XOR_MULT_DOSStub_20da {
  strings:
    $key_20da = { 74 b2 [2] 00 aa [2] 47 a8 [2] 00 b9 [2] 4e b5 [2] 42 bf [2] 55 b4 [2] 4e fa [2] 73 }

  condition:
    any of them
}