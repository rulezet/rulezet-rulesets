rule TTP_XOR_MULT_DOSStub_45aa {
  strings:
    $key_45aa = { 11 c2 [2] 65 da [2] 22 d8 [2] 65 c9 [2] 2b c5 [2] 27 cf [2] 30 c4 [2] 2b 8a [2] 16 }

  condition:
    any of them
}