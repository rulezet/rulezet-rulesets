rule TTP_XOR_MULT_DOSStub_67ad {
  strings:
    $key_67ad = { 33 c5 [2] 47 dd [2] 00 df [2] 47 ce [2] 09 c2 [2] 05 c8 [2] 12 c3 [2] 09 8d [2] 34 }

  condition:
    any of them
}