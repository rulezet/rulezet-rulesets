rule TTP_XOR_MULT_DOSStub_62b5 {
  strings:
    $key_62b5 = { 36 dd [2] 42 c5 [2] 05 c7 [2] 42 d6 [2] 0c da [2] 00 d0 [2] 17 db [2] 0c 95 [2] 31 }

  condition:
    any of them
}