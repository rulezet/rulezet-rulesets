rule TTP_XOR_MULT_DOSStub_53da {
  strings:
    $key_53da = { 07 b2 [2] 73 aa [2] 34 a8 [2] 73 b9 [2] 3d b5 [2] 31 bf [2] 26 b4 [2] 3d fa [2] 00 }

  condition:
    any of them
}