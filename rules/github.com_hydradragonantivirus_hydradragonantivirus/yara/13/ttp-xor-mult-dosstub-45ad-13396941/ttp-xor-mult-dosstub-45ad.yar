rule TTP_XOR_MULT_DOSStub_45ad {
  strings:
    $key_45ad = { 11 c5 [2] 65 dd [2] 22 df [2] 65 ce [2] 2b c2 [2] 27 c8 [2] 30 c3 [2] 2b 8d [2] 16 }

  condition:
    any of them
}