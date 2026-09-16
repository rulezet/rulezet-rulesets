rule TTP_XOR_MULT_DOSStub_a6b8 {
  strings:
    $key_a6b8 = { f2 d0 [2] 86 c8 [2] c1 ca [2] 86 db [2] c8 d7 [2] c4 dd [2] d3 d6 [2] c8 98 [2] f5 }

  condition:
    any of them
}