rule TTP_XOR_MULT_DOSStub_16da {
  strings:
    $key_16da = { 42 b2 [2] 36 aa [2] 71 a8 [2] 36 b9 [2] 78 b5 [2] 74 bf [2] 63 b4 [2] 78 fa [2] 45 }

  condition:
    any of them
}