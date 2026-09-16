rule TTP_XOR_MULT_DOSStub_e3b3 {
  strings:
    $key_e3b3 = { b7 db [2] c3 c3 [2] 84 c1 [2] c3 d0 [2] 8d dc [2] 81 d6 [2] 96 dd [2] 8d 93 [2] b0 }

  condition:
    any of them
}