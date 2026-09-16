rule TTP_XOR_MULT_DOSStub_a1b3 {
  strings:
    $key_a1b3 = { f5 db [2] 81 c3 [2] c6 c1 [2] 81 d0 [2] cf dc [2] c3 d6 [2] d4 dd [2] cf 93 [2] f2 }

  condition:
    any of them
}