rule TTP_XOR_MULT_DOSStub_e0b5 {
  strings:
    $key_e0b5 = { b4 dd [2] c0 c5 [2] 87 c7 [2] c0 d6 [2] 8e da [2] 82 d0 [2] 95 db [2] 8e 95 [2] b3 }

  condition:
    any of them
}