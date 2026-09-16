rule TTP_XOR_MULT_DOSStub_f1b5 {
  strings:
    $key_f1b5 = { a5 dd [2] d1 c5 [2] 96 c7 [2] d1 d6 [2] 9f da [2] 93 d0 [2] 84 db [2] 9f 95 [2] a2 }

  condition:
    any of them
}