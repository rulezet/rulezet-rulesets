rule TTP_XOR_MULT_DOSStub_09ad {
  strings:
    $key_09ad = { 5d c5 [2] 29 dd [2] 6e df [2] 29 ce [2] 67 c2 [2] 6b c8 [2] 7c c3 [2] 67 8d [2] 5a }

  condition:
    any of them
}