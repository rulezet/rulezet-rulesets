rule TTP_XOR_MULT_DOSStub_e5b5 {
  strings:
    $key_e5b5 = { b1 dd [2] c5 c5 [2] 82 c7 [2] c5 d6 [2] 8b da [2] 87 d0 [2] 90 db [2] 8b 95 [2] b6 }

  condition:
    any of them
}