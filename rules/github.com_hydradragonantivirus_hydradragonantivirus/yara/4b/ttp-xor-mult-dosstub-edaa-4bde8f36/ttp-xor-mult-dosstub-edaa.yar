rule TTP_XOR_MULT_DOSStub_edaa {
  strings:
    $key_edaa = { b9 c2 [2] cd da [2] 8a d8 [2] cd c9 [2] 83 c5 [2] 8f cf [2] 98 c4 [2] 83 8a [2] be }

  condition:
    any of them
}