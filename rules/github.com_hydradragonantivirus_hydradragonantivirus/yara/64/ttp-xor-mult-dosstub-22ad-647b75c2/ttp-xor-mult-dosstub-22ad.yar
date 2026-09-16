rule TTP_XOR_MULT_DOSStub_22ad {
  strings:
    $key_22ad = { 76 c5 [2] 02 dd [2] 45 df [2] 02 ce [2] 4c c2 [2] 40 c8 [2] 57 c3 [2] 4c 8d [2] 71 }

  condition:
    any of them
}