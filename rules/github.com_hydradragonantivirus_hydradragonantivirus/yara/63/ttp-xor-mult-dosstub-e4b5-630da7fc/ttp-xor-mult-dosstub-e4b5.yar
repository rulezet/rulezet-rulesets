rule TTP_XOR_MULT_DOSStub_e4b5 {
  strings:
    $key_e4b5 = { b0 dd [2] c4 c5 [2] 83 c7 [2] c4 d6 [2] 8a da [2] 86 d0 [2] 91 db [2] 8a 95 [2] b7 }

  condition:
    any of them
}