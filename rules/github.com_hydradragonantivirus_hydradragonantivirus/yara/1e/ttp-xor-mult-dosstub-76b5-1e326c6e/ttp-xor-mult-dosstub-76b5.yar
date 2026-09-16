rule TTP_XOR_MULT_DOSStub_76b5 {
  strings:
    $key_76b5 = { 22 dd [2] 56 c5 [2] 11 c7 [2] 56 d6 [2] 18 da [2] 14 d0 [2] 03 db [2] 18 95 [2] 25 }

  condition:
    any of them
}