rule TTP_XOR_MULT_DOSStub_62ad {
  strings:
    $key_62ad = { 36 c5 [2] 42 dd [2] 05 df [2] 42 ce [2] 0c c2 [2] 00 c8 [2] 17 c3 [2] 0c 8d [2] 31 }

  condition:
    any of them
}