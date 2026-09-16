rule TTP_XOR_MULT_DOSStub_a2b8 {
  strings:
    $key_a2b8 = { f6 d0 [2] 82 c8 [2] c5 ca [2] 82 db [2] cc d7 [2] c0 dd [2] d7 d6 [2] cc 98 [2] f1 }

  condition:
    any of them
}