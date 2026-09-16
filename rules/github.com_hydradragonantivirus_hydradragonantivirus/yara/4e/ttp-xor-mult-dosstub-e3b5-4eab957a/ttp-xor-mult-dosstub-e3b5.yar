rule TTP_XOR_MULT_DOSStub_e3b5 {
  strings:
    $key_e3b5 = { b7 dd [2] c3 c5 [2] 84 c7 [2] c3 d6 [2] 8d da [2] 81 d0 [2] 96 db [2] 8d 95 [2] b0 }

  condition:
    any of them
}