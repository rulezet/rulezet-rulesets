rule TTP_XOR_MULT_DOSStub_54b5 {
  strings:
    $key_54b5 = { 00 dd [2] 74 c5 [2] 33 c7 [2] 74 d6 [2] 3a da [2] 36 d0 [2] 21 db [2] 3a 95 [2] 07 }

  condition:
    any of them
}