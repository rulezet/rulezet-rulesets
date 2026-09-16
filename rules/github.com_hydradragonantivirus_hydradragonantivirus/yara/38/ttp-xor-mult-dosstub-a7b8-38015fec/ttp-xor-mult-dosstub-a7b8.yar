rule TTP_XOR_MULT_DOSStub_a7b8 {
  strings:
    $key_a7b8 = { f3 d0 [2] 87 c8 [2] c0 ca [2] 87 db [2] c9 d7 [2] c5 dd [2] d2 d6 [2] c9 98 [2] f4 }

  condition:
    any of them
}