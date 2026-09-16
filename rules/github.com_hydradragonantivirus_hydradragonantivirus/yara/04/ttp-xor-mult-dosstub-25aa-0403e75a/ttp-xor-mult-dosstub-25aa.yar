rule TTP_XOR_MULT_DOSStub_25aa {
  strings:
    $key_25aa = { 71 c2 [2] 05 da [2] 42 d8 [2] 05 c9 [2] 4b c5 [2] 47 cf [2] 50 c4 [2] 4b 8a [2] 76 }

  condition:
    any of them
}