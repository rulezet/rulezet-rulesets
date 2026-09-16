rule TTP_XOR_MULT_DOSStub_baad {
  strings:
    $key_baad = { ee c5 [2] 9a dd [2] dd df [2] 9a ce [2] d4 c2 [2] d8 c8 [2] cf c3 [2] d4 8d [2] e9 }

  condition:
    any of them
}