rule TTP_XOR_MULT_DOSStub_30aa {
  strings:
    $key_30aa = { 64 c2 [2] 10 da [2] 57 d8 [2] 10 c9 [2] 5e c5 [2] 52 cf [2] 45 c4 [2] 5e 8a [2] 63 }

  condition:
    any of them
}