rule TTP_XOR_MULT_DOSStub_93b2 {
  strings:
    $key_93b2 = { c7 da [2] b3 c2 [2] f4 c0 [2] b3 d1 [2] fd dd [2] f1 d7 [2] e6 dc [2] fd 92 [2] c0 }

  condition:
    any of them
}