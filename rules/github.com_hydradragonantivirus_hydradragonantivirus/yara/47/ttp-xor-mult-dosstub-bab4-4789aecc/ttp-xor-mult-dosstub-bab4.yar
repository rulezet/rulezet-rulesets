rule TTP_XOR_MULT_DOSStub_bab4 {
  strings:
    $key_bab4 = { ee dc [2] 9a c4 [2] dd c6 [2] 9a d7 [2] d4 db [2] d8 d1 [2] cf da [2] d4 94 [2] e9 }

  condition:
    any of them
}