rule TTP_XOR_MULT_DOSStub_e3a6 {
  strings:
    $key_e3a6 = { b7 ce [2] c3 d6 [2] 84 d4 [2] c3 c5 [2] 8d c9 [2] 81 c3 [2] 96 c8 [2] 8d 86 [2] b0 }

  condition:
    any of them
}