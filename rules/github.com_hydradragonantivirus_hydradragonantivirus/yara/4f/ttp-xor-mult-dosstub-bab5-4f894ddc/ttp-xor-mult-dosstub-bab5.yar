rule TTP_XOR_MULT_DOSStub_bab5 {
  strings:
    $key_bab5 = { ee dd [2] 9a c5 [2] dd c7 [2] 9a d6 [2] d4 da [2] d8 d0 [2] cf db [2] d4 95 [2] e9 }

  condition:
    any of them
}