rule TTP_XOR_MULT_DOSStub_27b3 {
  strings:
    $key_27b3 = { 73 db [2] 07 c3 [2] 40 c1 [2] 07 d0 [2] 49 dc [2] 45 d6 [2] 52 dd [2] 49 93 [2] 74 }

  condition:
    any of them
}