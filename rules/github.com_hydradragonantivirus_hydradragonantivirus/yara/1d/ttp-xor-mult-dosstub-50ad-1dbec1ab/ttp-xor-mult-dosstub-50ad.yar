rule TTP_XOR_MULT_DOSStub_50ad {
  strings:
    $key_50ad = { 04 c5 [2] 70 dd [2] 37 df [2] 70 ce [2] 3e c2 [2] 32 c8 [2] 25 c3 [2] 3e 8d [2] 03 }

  condition:
    any of them
}