rule TTP_XOR_MULT_DOSStub_71b3 {
  strings:
    $key_71b3 = { 25 db [2] 51 c3 [2] 16 c1 [2] 51 d0 [2] 1f dc [2] 13 d6 [2] 04 dd [2] 1f 93 [2] 22 }

  condition:
    any of them
}