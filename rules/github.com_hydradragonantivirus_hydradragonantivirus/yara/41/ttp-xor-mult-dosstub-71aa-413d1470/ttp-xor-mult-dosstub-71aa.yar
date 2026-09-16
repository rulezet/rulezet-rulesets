rule TTP_XOR_MULT_DOSStub_71aa {
  strings:
    $key_71aa = { 25 c2 [2] 51 da [2] 16 d8 [2] 51 c9 [2] 1f c5 [2] 13 cf [2] 04 c4 [2] 1f 8a [2] 22 }

  condition:
    any of them
}