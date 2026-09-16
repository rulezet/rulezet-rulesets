rule TTP_XOR_MULT_DOSStub_66ad {
  strings:
    $key_66ad = { 32 c5 [2] 46 dd [2] 01 df [2] 46 ce [2] 08 c2 [2] 04 c8 [2] 13 c3 [2] 08 8d [2] 35 }

  condition:
    any of them
}