rule TTP_XOR_MULT_DOSStub_b9a1 {
  strings:
    $key_b9a1 = { ed c9 [2] 99 d1 [2] de d3 [2] 99 c2 [2] d7 ce [2] db c4 [2] cc cf [2] d7 81 [2] ea }

  condition:
    any of them
}