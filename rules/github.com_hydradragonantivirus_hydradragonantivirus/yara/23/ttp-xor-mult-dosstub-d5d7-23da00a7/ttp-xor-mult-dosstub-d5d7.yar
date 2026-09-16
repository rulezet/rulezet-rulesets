rule TTP_XOR_MULT_DOSStub_d5d7 {
  strings:
    $key_d5d7 = { 81 bf [2] f5 a7 [2] b2 a5 [2] f5 b4 [2] bb b8 [2] b7 b2 [2] a0 b9 [2] bb f7 [2] 86 }

  condition:
    any of them
}