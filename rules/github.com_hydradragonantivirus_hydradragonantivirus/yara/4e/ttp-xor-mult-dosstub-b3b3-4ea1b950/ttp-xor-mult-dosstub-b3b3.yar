rule TTP_XOR_MULT_DOSStub_b3b3 {
  strings:
    $key_b3b3 = { e7 db [2] 93 c3 [2] d4 c1 [2] 93 d0 [2] dd dc [2] d1 d6 [2] c6 dd [2] dd 93 [2] e0 }

  condition:
    any of them
}