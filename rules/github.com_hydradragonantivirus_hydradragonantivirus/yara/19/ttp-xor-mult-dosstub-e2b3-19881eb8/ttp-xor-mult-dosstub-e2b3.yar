rule TTP_XOR_MULT_DOSStub_e2b3 {
  strings:
    $key_e2b3 = { b6 db [2] c2 c3 [2] 85 c1 [2] c2 d0 [2] 8c dc [2] 80 d6 [2] 97 dd [2] 8c 93 [2] b1 }

  condition:
    any of them
}