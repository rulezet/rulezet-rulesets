rule TTP_XOR_MULT_DOSStub_70aa {
  strings:
    $key_70aa = { 24 c2 [2] 50 da [2] 17 d8 [2] 50 c9 [2] 1e c5 [2] 12 cf [2] 05 c4 [2] 1e 8a [2] 23 }

  condition:
    any of them
}