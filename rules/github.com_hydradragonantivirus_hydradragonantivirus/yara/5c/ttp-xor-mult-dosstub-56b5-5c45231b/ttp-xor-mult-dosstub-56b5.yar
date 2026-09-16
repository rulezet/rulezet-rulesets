rule TTP_XOR_MULT_DOSStub_56b5 {
  strings:
    $key_56b5 = { 02 dd [2] 76 c5 [2] 31 c7 [2] 76 d6 [2] 38 da [2] 34 d0 [2] 23 db [2] 38 95 [2] 05 }

  condition:
    any of them
}