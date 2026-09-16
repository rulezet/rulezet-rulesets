rule TTP_XOR_MULT_DOSStub_baa8 {
  strings:
    $key_baa8 = { ee c0 [2] 9a d8 [2] dd da [2] 9a cb [2] d4 c7 [2] d8 cd [2] cf c6 [2] d4 88 [2] e9 }

  condition:
    any of them
}