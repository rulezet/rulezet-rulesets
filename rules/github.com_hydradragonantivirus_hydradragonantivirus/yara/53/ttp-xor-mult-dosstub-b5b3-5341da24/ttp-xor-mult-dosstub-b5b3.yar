rule TTP_XOR_MULT_DOSStub_b5b3 {
  strings:
    $key_b5b3 = { e1 db [2] 95 c3 [2] d2 c1 [2] 95 d0 [2] db dc [2] d7 d6 [2] c0 dd [2] db 93 [2] e6 }

  condition:
    any of them
}