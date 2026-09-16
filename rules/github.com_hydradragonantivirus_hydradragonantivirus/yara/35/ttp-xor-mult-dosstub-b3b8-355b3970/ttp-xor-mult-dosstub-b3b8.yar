rule TTP_XOR_MULT_DOSStub_b3b8 {
  strings:
    $key_b3b8 = { e7 d0 [2] 93 c8 [2] d4 ca [2] 93 db [2] dd d7 [2] d1 dd [2] c6 d6 [2] dd 98 [2] e0 }

  condition:
    any of them
}