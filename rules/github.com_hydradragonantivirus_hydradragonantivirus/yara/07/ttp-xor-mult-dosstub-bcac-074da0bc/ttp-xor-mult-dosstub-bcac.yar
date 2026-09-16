rule TTP_XOR_MULT_DOSStub_bcac {
  strings:
    $key_bcac = { e8 c4 [2] 9c dc [2] db de [2] 9c cf [2] d2 c3 [2] de c9 [2] c9 c2 [2] d2 8c [2] ef }

  condition:
    any of them
}