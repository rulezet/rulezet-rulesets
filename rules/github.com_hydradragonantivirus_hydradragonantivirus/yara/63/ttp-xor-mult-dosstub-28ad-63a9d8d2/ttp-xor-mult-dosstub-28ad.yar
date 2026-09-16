rule TTP_XOR_MULT_DOSStub_28ad {
  strings:
    $key_28ad = { 7c c5 [2] 08 dd [2] 4f df [2] 08 ce [2] 46 c2 [2] 4a c8 [2] 5d c3 [2] 46 8d [2] 7b }

  condition:
    any of them
}