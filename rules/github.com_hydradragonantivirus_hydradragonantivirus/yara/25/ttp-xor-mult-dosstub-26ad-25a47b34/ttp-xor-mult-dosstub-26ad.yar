rule TTP_XOR_MULT_DOSStub_26ad {
  strings:
    $key_26ad = { 72 c5 [2] 06 dd [2] 41 df [2] 06 ce [2] 48 c2 [2] 44 c8 [2] 53 c3 [2] 48 8d [2] 75 }

  condition:
    any of them
}