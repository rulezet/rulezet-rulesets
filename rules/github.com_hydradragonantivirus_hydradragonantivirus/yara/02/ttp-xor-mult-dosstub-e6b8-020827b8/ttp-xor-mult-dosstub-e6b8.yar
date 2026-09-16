rule TTP_XOR_MULT_DOSStub_e6b8 {
  strings:
    $key_e6b8 = { b2 d0 [2] c6 c8 [2] 81 ca [2] c6 db [2] 88 d7 [2] 84 dd [2] 93 d6 [2] 88 98 [2] b5 }

  condition:
    any of them
}