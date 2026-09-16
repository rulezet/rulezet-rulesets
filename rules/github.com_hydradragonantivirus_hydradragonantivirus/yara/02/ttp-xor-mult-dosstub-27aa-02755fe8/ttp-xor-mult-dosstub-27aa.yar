rule TTP_XOR_MULT_DOSStub_27aa {
  strings:
    $key_27aa = { 73 c2 [2] 07 da [2] 40 d8 [2] 07 c9 [2] 49 c5 [2] 45 cf [2] 52 c4 [2] 49 8a [2] 74 }

  condition:
    any of them
}