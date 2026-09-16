rule TTP_XOR_MULT_DOSStub_63ad {
  strings:
    $key_63ad = { 37 c5 [2] 43 dd [2] 04 df [2] 43 ce [2] 0d c2 [2] 01 c8 [2] 16 c3 [2] 0d 8d [2] 30 }

  condition:
    any of them
}