rule TTP_XOR_MULT_DOSStub_77ad {
  strings:
    $key_77ad = { 23 c5 [2] 57 dd [2] 10 df [2] 57 ce [2] 19 c2 [2] 15 c8 [2] 02 c3 [2] 19 8d [2] 24 }

  condition:
    any of them
}