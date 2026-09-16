rule TTP_XOR_MULT_DOSStub_17ad {
  strings:
    $key_17ad = { 43 c5 [2] 37 dd [2] 70 df [2] 37 ce [2] 79 c2 [2] 75 c8 [2] 62 c3 [2] 79 8d [2] 44 }

  condition:
    any of them
}