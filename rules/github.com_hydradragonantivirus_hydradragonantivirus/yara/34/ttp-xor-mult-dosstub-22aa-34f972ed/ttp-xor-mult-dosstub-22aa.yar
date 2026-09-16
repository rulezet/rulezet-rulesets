rule TTP_XOR_MULT_DOSStub_22aa {
  strings:
    $key_22aa = { 76 c2 [2] 02 da [2] 45 d8 [2] 02 c9 [2] 4c c5 [2] 40 cf [2] 57 c4 [2] 4c 8a [2] 71 }

  condition:
    any of them
}