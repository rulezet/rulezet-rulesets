rule TTP_XOR_MULT_DOSStub_72aa {
  strings:
    $key_72aa = { 26 c2 [2] 52 da [2] 15 d8 [2] 52 c9 [2] 1c c5 [2] 10 cf [2] 07 c4 [2] 1c 8a [2] 21 }

  condition:
    any of them
}