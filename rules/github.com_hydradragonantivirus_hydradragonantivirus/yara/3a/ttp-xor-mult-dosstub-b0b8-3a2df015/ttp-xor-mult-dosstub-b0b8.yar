rule TTP_XOR_MULT_DOSStub_b0b8 {
  strings:
    $key_b0b8 = { e4 d0 [2] 90 c8 [2] d7 ca [2] 90 db [2] de d7 [2] d2 dd [2] c5 d6 [2] de 98 [2] e3 }

  condition:
    any of them
}