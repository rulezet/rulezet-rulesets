rule TTP_XOR_MULT_DOSStub_b5b8 {
  strings:
    $key_b5b8 = { e1 d0 [2] 95 c8 [2] d2 ca [2] 95 db [2] db d7 [2] d7 dd [2] c0 d6 [2] db 98 [2] e6 }

  condition:
    any of them
}