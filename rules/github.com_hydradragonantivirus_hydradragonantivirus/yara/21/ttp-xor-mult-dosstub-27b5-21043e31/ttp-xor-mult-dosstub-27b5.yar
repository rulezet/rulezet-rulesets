rule TTP_XOR_MULT_DOSStub_27b5 {
  strings:
    $key_27b5 = { 73 dd [2] 07 c5 [2] 40 c7 [2] 07 d6 [2] 49 da [2] 45 d0 [2] 52 db [2] 49 95 [2] 74 }

  condition:
    any of them
}