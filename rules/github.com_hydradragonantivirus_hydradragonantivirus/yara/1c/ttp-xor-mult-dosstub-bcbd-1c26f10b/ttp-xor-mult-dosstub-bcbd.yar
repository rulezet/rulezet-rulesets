rule TTP_XOR_MULT_DOSStub_bcbd {
  strings:
    $key_bcbd = { e8 d5 [2] 9c cd [2] db cf [2] 9c de [2] d2 d2 [2] de d8 [2] c9 d3 [2] d2 9d [2] ef }

  condition:
    any of them
}