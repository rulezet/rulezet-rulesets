rule TTP_XOR_MULT_DOSStub_bfa1 {
  strings:
    $key_bfa1 = { eb c9 [2] 9f d1 [2] d8 d3 [2] 9f c2 [2] d1 ce [2] dd c4 [2] ca cf [2] d1 81 [2] ec }

  condition:
    any of them
}