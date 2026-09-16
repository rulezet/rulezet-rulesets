rule TTP_XOR_MULT_DOSStub_68ad {
  strings:
    $key_68ad = { 3c c5 [2] 48 dd [2] 0f df [2] 48 ce [2] 06 c2 [2] 0a c8 [2] 1d c3 [2] 06 8d [2] 3b }

  condition:
    any of them
}