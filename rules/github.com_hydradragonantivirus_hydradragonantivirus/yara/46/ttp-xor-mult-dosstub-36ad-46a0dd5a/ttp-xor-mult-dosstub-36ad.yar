rule TTP_XOR_MULT_DOSStub_36ad {
  strings:
    $key_36ad = { 62 c5 [2] 16 dd [2] 51 df [2] 16 ce [2] 58 c2 [2] 54 c8 [2] 43 c3 [2] 58 8d [2] 65 }

  condition:
    any of them
}