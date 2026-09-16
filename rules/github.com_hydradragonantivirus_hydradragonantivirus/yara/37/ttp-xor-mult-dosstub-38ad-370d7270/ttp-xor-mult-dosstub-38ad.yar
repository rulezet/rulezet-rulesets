rule TTP_XOR_MULT_DOSStub_38ad {
  strings:
    $key_38ad = { 6c c5 [2] 18 dd [2] 5f df [2] 18 ce [2] 56 c2 [2] 5a c8 [2] 4d c3 [2] 56 8d [2] 6b }

  condition:
    any of them
}