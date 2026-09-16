rule TTP_XOR_MULT_DOSStub_bfaa {
  strings:
    $key_bfaa = { eb c2 [2] 9f da [2] d8 d8 [2] 9f c9 [2] d1 c5 [2] dd cf [2] ca c4 [2] d1 8a [2] ec }

  condition:
    any of them
}