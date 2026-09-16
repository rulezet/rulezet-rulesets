rule TTP_XOR_MULT_DOSStub_f9ad {
  strings:
    $key_f9ad = { ad c5 [2] d9 dd [2] 9e df [2] d9 ce [2] 97 c2 [2] 9b c8 [2] 8c c3 [2] 97 8d [2] aa }

  condition:
    any of them
}