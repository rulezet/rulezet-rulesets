rule TTP_XOR_MULT_DOSStub_31ad {
  strings:
    $key_31ad = { 65 c5 [2] 11 dd [2] 56 df [2] 11 ce [2] 5f c2 [2] 53 c8 [2] 44 c3 [2] 5f 8d [2] 62 }

  condition:
    any of them
}