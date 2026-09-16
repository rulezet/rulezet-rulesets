rule TTP_XOR_MULT_DOSStub_5ab5 {
  strings:
    $key_5ab5 = { 0e dd [2] 7a c5 [2] 3d c7 [2] 7a d6 [2] 34 da [2] 38 d0 [2] 2f db [2] 34 95 [2] 09 }

  condition:
    any of them
}