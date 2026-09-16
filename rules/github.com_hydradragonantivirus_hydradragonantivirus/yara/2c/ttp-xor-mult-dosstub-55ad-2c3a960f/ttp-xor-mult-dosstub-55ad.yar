rule TTP_XOR_MULT_DOSStub_55ad {
  strings:
    $key_55ad = { 01 c5 [2] 75 dd [2] 32 df [2] 75 ce [2] 3b c2 [2] 37 c8 [2] 20 c3 [2] 3b 8d [2] 06 }

  condition:
    any of them
}