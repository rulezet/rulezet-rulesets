rule TTP_XOR_MULT_DOSStub_bcaa {
  strings:
    $key_bcaa = { e8 c2 [2] 9c da [2] db d8 [2] 9c c9 [2] d2 c5 [2] de cf [2] c9 c4 [2] d2 8a [2] ef }

  condition:
    any of them
}