rule TTP_XOR_MULT_DOSStub_07aa {
  strings:
    $key_07aa = { 53 c2 [2] 27 da [2] 60 d8 [2] 27 c9 [2] 69 c5 [2] 65 cf [2] 72 c4 [2] 69 8a [2] 54 }

  condition:
    any of them
}