rule TTP_XOR_MULT_DOSStub_56b3 {
  strings:
    $key_56b3 = { 02 db [2] 76 c3 [2] 31 c1 [2] 76 d0 [2] 38 dc [2] 34 d6 [2] 23 dd [2] 38 93 [2] 05 }

  condition:
    any of them
}