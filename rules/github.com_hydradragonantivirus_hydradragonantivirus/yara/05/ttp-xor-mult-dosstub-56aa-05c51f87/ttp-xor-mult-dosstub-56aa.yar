rule TTP_XOR_MULT_DOSStub_56aa {
  strings:
    $key_56aa = { 02 c2 [2] 76 da [2] 31 d8 [2] 76 c9 [2] 38 c5 [2] 34 cf [2] 23 c4 [2] 38 8a [2] 05 }

  condition:
    any of them
}