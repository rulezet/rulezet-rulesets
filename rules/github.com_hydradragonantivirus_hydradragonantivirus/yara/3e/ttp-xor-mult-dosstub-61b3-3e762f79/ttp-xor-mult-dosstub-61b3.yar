rule TTP_XOR_MULT_DOSStub_61b3 {
  strings:
    $key_61b3 = { 35 db [2] 41 c3 [2] 06 c1 [2] 41 d0 [2] 0f dc [2] 03 d6 [2] 14 dd [2] 0f 93 [2] 32 }

  condition:
    any of them
}