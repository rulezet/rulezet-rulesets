rule TTP_XOR_MULT_DOSStub_30da {
  strings:
    $key_30da = { 64 b2 [2] 10 aa [2] 57 a8 [2] 10 b9 [2] 5e b5 [2] 52 bf [2] 45 b4 [2] 5e fa [2] 63 }

  condition:
    any of them
}