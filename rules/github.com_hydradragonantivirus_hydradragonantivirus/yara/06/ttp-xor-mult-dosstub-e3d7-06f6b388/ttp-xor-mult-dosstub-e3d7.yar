rule TTP_XOR_MULT_DOSStub_e3d7 {
  strings:
    $key_e3d7 = { b7 bf [2] c3 a7 [2] 84 a5 [2] c3 b4 [2] 8d b8 [2] 81 b2 [2] 96 b9 [2] 8d f7 [2] b0 }

  condition:
    any of them
}