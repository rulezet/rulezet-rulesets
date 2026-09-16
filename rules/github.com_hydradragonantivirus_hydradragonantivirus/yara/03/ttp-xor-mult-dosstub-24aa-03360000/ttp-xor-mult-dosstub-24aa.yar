rule TTP_XOR_MULT_DOSStub_24aa {
  strings:
    $key_24aa = { 70 c2 [2] 04 da [2] 43 d8 [2] 04 c9 [2] 4a c5 [2] 46 cf [2] 51 c4 [2] 4a 8a [2] 77 }

  condition:
    any of them
}