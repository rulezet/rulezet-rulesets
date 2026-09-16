rule TTP_XOR_MULT_DOSStub_60aa {
  strings:
    $key_60aa = { 34 c2 [2] 40 da [2] 07 d8 [2] 40 c9 [2] 0e c5 [2] 02 cf [2] 15 c4 [2] 0e 8a [2] 33 }

  condition:
    any of them
}