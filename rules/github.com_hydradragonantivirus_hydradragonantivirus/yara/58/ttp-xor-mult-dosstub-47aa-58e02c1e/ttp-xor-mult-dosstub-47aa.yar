rule TTP_XOR_MULT_DOSStub_47aa {
  strings:
    $key_47aa = { 13 c2 [2] 67 da [2] 20 d8 [2] 67 c9 [2] 29 c5 [2] 25 cf [2] 32 c4 [2] 29 8a [2] 14 }

  condition:
    any of them
}