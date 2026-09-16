rule TTP_XOR_MULT_DOSStub_60ad {
  strings:
    $key_60ad = { 34 c5 [2] 40 dd [2] 07 df [2] 40 ce [2] 0e c2 [2] 02 c8 [2] 15 c3 [2] 0e 8d [2] 33 }

  condition:
    any of them
}