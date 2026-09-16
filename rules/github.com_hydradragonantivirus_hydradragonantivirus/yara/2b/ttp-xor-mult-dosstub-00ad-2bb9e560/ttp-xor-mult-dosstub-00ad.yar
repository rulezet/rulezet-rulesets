rule TTP_XOR_MULT_DOSStub_00ad {
  strings:
    $key_00ad = { 54 c5 [2] 20 dd [2] 67 df [2] 20 ce [2] 6e c2 [2] 62 c8 [2] 75 c3 [2] 6e 8d [2] 53 }

  condition:
    any of them
}