rule TTP_XOR_MULT_DOSStub_10b5 {
  strings:
    $key_10b5 = { 44 dd [2] 30 c5 [2] 77 c7 [2] 30 d6 [2] 7e da [2] 72 d0 [2] 65 db [2] 7e 95 [2] 43 }

  condition:
    any of them
}