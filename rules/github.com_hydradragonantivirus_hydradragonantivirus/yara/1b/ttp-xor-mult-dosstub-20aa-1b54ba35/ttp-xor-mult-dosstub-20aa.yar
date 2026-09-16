rule TTP_XOR_MULT_DOSStub_20aa {
  strings:
    $key_20aa = { 74 c2 [2] 00 da [2] 47 d8 [2] 00 c9 [2] 4e c5 [2] 42 cf [2] 55 c4 [2] 4e 8a [2] 73 }

  condition:
    any of them
}