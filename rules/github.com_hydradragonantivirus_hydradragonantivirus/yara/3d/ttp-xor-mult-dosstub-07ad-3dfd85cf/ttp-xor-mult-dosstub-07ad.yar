rule TTP_XOR_MULT_DOSStub_07ad {
  strings:
    $key_07ad = { 53 c5 [2] 27 dd [2] 60 df [2] 27 ce [2] 69 c2 [2] 65 c8 [2] 72 c3 [2] 69 8d [2] 54 }

  condition:
    any of them
}