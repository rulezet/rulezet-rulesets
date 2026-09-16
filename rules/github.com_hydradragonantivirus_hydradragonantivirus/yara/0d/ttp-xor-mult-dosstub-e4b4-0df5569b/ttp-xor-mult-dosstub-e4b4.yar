rule TTP_XOR_MULT_DOSStub_e4b4 {
  strings:
    $key_e4b4 = { b0 dc [2] c4 c4 [2] 83 c6 [2] c4 d7 [2] 8a db [2] 86 d1 [2] 91 da [2] 8a 94 [2] b7 }

  condition:
    any of them
}