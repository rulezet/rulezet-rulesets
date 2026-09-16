rule TTP_XOR_MULT_DOSStub_42ad {
  strings:
    $key_42ad = { 16 c5 [2] 62 dd [2] 25 df [2] 62 ce [2] 2c c2 [2] 20 c8 [2] 37 c3 [2] 2c 8d [2] 11 }

  condition:
    any of them
}