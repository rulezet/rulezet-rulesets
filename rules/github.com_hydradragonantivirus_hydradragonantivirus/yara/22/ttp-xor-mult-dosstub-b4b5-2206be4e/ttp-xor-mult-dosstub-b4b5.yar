rule TTP_XOR_MULT_DOSStub_b4b5 {
  strings:
    $key_b4b5 = { e0 dd [2] 94 c5 [2] d3 c7 [2] 94 d6 [2] da da [2] d6 d0 [2] c1 db [2] da 95 [2] e7 }

  condition:
    any of them
}