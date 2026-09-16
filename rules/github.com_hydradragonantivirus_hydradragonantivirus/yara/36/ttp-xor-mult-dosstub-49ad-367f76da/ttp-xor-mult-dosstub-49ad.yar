rule TTP_XOR_MULT_DOSStub_49ad {
  strings:
    $key_49ad = { 1d c5 [2] 69 dd [2] 2e df [2] 69 ce [2] 27 c2 [2] 2b c8 [2] 3c c3 [2] 27 8d [2] 1a }

  condition:
    any of them
}