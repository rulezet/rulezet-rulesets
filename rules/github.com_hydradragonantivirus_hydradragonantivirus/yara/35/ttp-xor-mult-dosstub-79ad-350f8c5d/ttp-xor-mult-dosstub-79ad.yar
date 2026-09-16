rule TTP_XOR_MULT_DOSStub_79ad {
  strings:
    $key_79ad = { 2d c5 [2] 59 dd [2] 1e df [2] 59 ce [2] 17 c2 [2] 1b c8 [2] 0c c3 [2] 17 8d [2] 2a }

  condition:
    any of them
}