rule TTP_XOR_MULT_DOSStub_baa9 {
  strings:
    $key_baa9 = { ee c1 [2] 9a d9 [2] dd db [2] 9a ca [2] d4 c6 [2] d8 cc [2] cf c7 [2] d4 89 [2] e9 }

  condition:
    any of them
}