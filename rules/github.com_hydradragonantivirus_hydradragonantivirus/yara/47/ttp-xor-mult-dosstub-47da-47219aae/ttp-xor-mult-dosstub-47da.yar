rule TTP_XOR_MULT_DOSStub_47da {
  strings:
    $key_47da = { 13 b2 [2] 67 aa [2] 20 a8 [2] 67 b9 [2] 29 b5 [2] 25 bf [2] 32 b4 [2] 29 fa [2] 14 }

  condition:
    any of them
}