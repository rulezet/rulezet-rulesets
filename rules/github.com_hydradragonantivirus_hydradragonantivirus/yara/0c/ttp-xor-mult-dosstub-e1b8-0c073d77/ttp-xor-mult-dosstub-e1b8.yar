rule TTP_XOR_MULT_DOSStub_e1b8 {
  strings:
    $key_e1b8 = { b5 d0 [2] c1 c8 [2] 86 ca [2] c1 db [2] 8f d7 [2] 83 dd [2] 94 d6 [2] 8f 98 [2] b2 }

  condition:
    any of them
}