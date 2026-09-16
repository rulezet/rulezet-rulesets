rule TTP_XOR_MULT_DOSStub_b7b5 {
  strings:
    $key_b7b5 = { e3 dd [2] 97 c5 [2] d0 c7 [2] 97 d6 [2] d9 da [2] d5 d0 [2] c2 db [2] d9 95 [2] e4 }

  condition:
    any of them
}