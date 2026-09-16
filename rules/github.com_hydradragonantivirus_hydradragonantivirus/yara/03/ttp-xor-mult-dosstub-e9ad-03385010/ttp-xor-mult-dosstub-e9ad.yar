rule TTP_XOR_MULT_DOSStub_e9ad {
  strings:
    $key_e9ad = { bd c5 [2] c9 dd [2] 8e df [2] c9 ce [2] 87 c2 [2] 8b c8 [2] 9c c3 [2] 87 8d [2] ba }

  condition:
    any of them
}