rule TTP_XOR_MULT_DOSStub_58ad {
  strings:
    $key_58ad = { 0c c5 [2] 78 dd [2] 3f df [2] 78 ce [2] 36 c2 [2] 3a c8 [2] 2d c3 [2] 36 8d [2] 0b }

  condition:
    any of them
}