rule TTP_XOR_MULT_DOSStub_01ad {
  strings:
    $key_01ad = { 55 c5 [2] 21 dd [2] 66 df [2] 21 ce [2] 6f c2 [2] 63 c8 [2] 74 c3 [2] 6f 8d [2] 52 }

  condition:
    any of them
}