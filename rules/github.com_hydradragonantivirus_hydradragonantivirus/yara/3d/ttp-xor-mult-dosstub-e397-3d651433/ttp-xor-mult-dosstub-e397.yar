rule TTP_XOR_MULT_DOSStub_e397 {
  strings:
    $key_e397 = { b7 ff [2] c3 e7 [2] 84 e5 [2] c3 f4 [2] 8d f8 [2] 81 f2 [2] 96 f9 [2] 8d b7 [2] b0 }

  condition:
    any of them
}