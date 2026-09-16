rule TTP_XOR_MULT_DOSStub_e4b3 {
  strings:
    $key_e4b3 = { b0 db [2] c4 c3 [2] 83 c1 [2] c4 d0 [2] 8a dc [2] 86 d6 [2] 91 dd [2] 8a 93 [2] b7 }

  condition:
    any of them
}