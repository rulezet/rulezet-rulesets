rule TTP_XOR_MULT_DOSStub_18ad {
  strings:
    $key_18ad = { 4c c5 [2] 38 dd [2] 7f df [2] 38 ce [2] 76 c2 [2] 7a c8 [2] 6d c3 [2] 76 8d [2] 4b }

  condition:
    any of them
}