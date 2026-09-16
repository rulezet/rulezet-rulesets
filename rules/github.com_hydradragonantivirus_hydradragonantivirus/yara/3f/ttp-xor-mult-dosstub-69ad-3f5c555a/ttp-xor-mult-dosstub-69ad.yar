rule TTP_XOR_MULT_DOSStub_69ad {
  strings:
    $key_69ad = { 3d c5 [2] 49 dd [2] 0e df [2] 49 ce [2] 07 c2 [2] 0b c8 [2] 1c c3 [2] 07 8d [2] 3a }

  condition:
    any of them
}