rule TTP_XOR_MULT_DOSStub_06aa {
  strings:
    $key_06aa = { 52 c2 [2] 26 da [2] 61 d8 [2] 26 c9 [2] 68 c5 [2] 64 cf [2] 73 c4 [2] 68 8a [2] 55 }

  condition:
    any of them
}