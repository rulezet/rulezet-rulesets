rule TTP_XOR_MULT_DOSStub_40aa {
  strings:
    $key_40aa = { 14 c2 [2] 60 da [2] 27 d8 [2] 60 c9 [2] 2e c5 [2] 22 cf [2] 35 c4 [2] 2e 8a [2] 13 }

  condition:
    any of them
}