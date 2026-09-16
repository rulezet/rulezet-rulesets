rule TTP_XOR_MULT_DOSStub_50da {
  strings:
    $key_50da = { 04 b2 [2] 70 aa [2] 37 a8 [2] 70 b9 [2] 3e b5 [2] 32 bf [2] 25 b4 [2] 3e fa [2] 03 }

  condition:
    any of them
}