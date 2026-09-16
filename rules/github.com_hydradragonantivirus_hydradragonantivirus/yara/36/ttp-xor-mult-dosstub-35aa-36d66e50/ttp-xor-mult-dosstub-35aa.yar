rule TTP_XOR_MULT_DOSStub_35aa {
  strings:
    $key_35aa = { 61 c2 [2] 15 da [2] 52 d8 [2] 15 c9 [2] 5b c5 [2] 57 cf [2] 40 c4 [2] 5b 8a [2] 66 }

  condition:
    any of them
}