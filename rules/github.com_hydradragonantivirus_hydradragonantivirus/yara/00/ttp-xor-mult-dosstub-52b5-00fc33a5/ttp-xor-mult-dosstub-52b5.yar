rule TTP_XOR_MULT_DOSStub_52b5 {
  strings:
    $key_52b5 = { 06 dd [2] 72 c5 [2] 35 c7 [2] 72 d6 [2] 3c da [2] 30 d0 [2] 27 db [2] 3c 95 [2] 01 }

  condition:
    any of them
}