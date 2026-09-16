rule TTP_XOR_MULT_DOSStub_12b5 {
  strings:
    $key_12b5 = { 46 dd [2] 32 c5 [2] 75 c7 [2] 32 d6 [2] 7c da [2] 70 d0 [2] 67 db [2] 7c 95 [2] 41 }

  condition:
    any of them
}