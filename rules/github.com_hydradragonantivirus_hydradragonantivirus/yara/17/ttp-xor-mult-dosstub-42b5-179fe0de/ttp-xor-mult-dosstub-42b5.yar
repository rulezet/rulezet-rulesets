rule TTP_XOR_MULT_DOSStub_42b5 {
  strings:
    $key_42b5 = { 16 dd [2] 62 c5 [2] 25 c7 [2] 62 d6 [2] 2c da [2] 20 d0 [2] 37 db [2] 2c 95 [2] 11 }

  condition:
    any of them
}