rule TTP_XOR_MULT_DOSStub_14ad {
  strings:
    $key_14ad = { 40 c5 [2] 34 dd [2] 73 df [2] 34 ce [2] 7a c2 [2] 76 c8 [2] 61 c3 [2] 7a 8d [2] 47 }

  condition:
    any of them
}