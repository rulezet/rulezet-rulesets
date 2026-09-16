rule TTP_XOR_MULT_DOSStub_03ad {
  strings:
    $key_03ad = { 57 c5 [2] 23 dd [2] 64 df [2] 23 ce [2] 6d c2 [2] 61 c8 [2] 76 c3 [2] 6d 8d [2] 50 }

  condition:
    any of them
}