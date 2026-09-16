rule TTP_XOR_MULT_DOSStub_b5b5 {
  strings:
    $key_b5b5 = { e1 dd [2] 95 c5 [2] d2 c7 [2] 95 d6 [2] db da [2] d7 d0 [2] c0 db [2] db 95 [2] e6 }

  condition:
    any of them
}