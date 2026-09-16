rule TTP_XOR_MULT_DOSStub_14b5 {
  strings:
    $key_14b5 = { 40 dd [2] 34 c5 [2] 73 c7 [2] 34 d6 [2] 7a da [2] 76 d0 [2] 61 db [2] 7a 95 [2] 47 }

  condition:
    any of them
}