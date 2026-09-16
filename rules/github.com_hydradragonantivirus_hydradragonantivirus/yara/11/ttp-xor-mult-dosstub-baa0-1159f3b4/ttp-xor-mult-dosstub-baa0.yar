rule TTP_XOR_MULT_DOSStub_baa0 {
  strings:
    $key_baa0 = { ee c8 [2] 9a d0 [2] dd d2 [2] 9a c3 [2] d4 cf [2] d8 c5 [2] cf ce [2] d4 80 [2] e9 }

  condition:
    any of them
}