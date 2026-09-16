rule TTP_XOR_MULT_DOSStub_bab1 {
  strings:
    $key_bab1 = { ee d9 [2] 9a c1 [2] dd c3 [2] 9a d2 [2] d4 de [2] d8 d4 [2] cf df [2] d4 91 [2] e9 }

  condition:
    any of them
}