rule TTP_XOR_MULT_DOSStub_28aa {
  strings:
    $key_28aa = { 7c c2 [2] 08 da [2] 4f d8 [2] 08 c9 [2] 46 c5 [2] 4a cf [2] 5d c4 [2] 46 8a [2] 7b }

  condition:
    any of them
}