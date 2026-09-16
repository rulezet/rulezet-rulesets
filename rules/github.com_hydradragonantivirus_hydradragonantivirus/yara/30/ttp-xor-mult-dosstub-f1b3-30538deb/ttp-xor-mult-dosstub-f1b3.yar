rule TTP_XOR_MULT_DOSStub_f1b3 {
  strings:
    $key_f1b3 = { a5 db [2] d1 c3 [2] 96 c1 [2] d1 d0 [2] 9f dc [2] 93 d6 [2] 84 dd [2] 9f 93 [2] a2 }

  condition:
    any of them
}