rule TTP_XOR_MULT_DOSStub_b9a0 {
  strings:
    $key_b9a0 = { ed c8 [2] 99 d0 [2] de d2 [2] 99 c3 [2] d7 cf [2] db c5 [2] cc ce [2] d7 80 [2] ea }

  condition:
    any of them
}