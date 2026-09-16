rule TTP_XOR_MULT_DOSStub_41b3 {
  strings:
    $key_41b3 = { 15 db [2] 61 c3 [2] 26 c1 [2] 61 d0 [2] 2f dc [2] 23 d6 [2] 34 dd [2] 2f 93 [2] 12 }

  condition:
    any of them
}