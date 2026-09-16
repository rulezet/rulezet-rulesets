rule TTP_XOR_MULT_DOSStub_53ad {
  strings:
    $key_53ad = { 07 c5 [2] 73 dd [2] 34 df [2] 73 ce [2] 3d c2 [2] 31 c8 [2] 26 c3 [2] 3d 8d [2] 00 }

  condition:
    any of them
}