rule TTP_XOR_MULT_DOSStub_64b5 {
  strings:
    $key_64b5 = { 30 dd [2] 44 c5 [2] 03 c7 [2] 44 d6 [2] 0a da [2] 06 d0 [2] 11 db [2] 0a 95 [2] 37 }

  condition:
    any of them
}