rule TTP_XOR_MULT_DOSStub_bab8 {
  strings:
    $key_bab8 = { ee d0 [2] 9a c8 [2] dd ca [2] 9a db [2] d4 d7 [2] d8 dd [2] cf d6 [2] d4 98 [2] e9 }

  condition:
    any of them
}