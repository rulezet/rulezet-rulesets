rule TTP_XOR_MULT_DOSStub_b7b3 {
  strings:
    $key_b7b3 = { e3 db [2] 97 c3 [2] d0 c1 [2] 97 d0 [2] d9 dc [2] d5 d6 [2] c2 dd [2] d9 93 [2] e4 }

  condition:
    any of them
}