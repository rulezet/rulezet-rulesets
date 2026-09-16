rule TTP_XOR_MULT_DOSStub_1aaa {
  strings:
    $key_1aaa = { 4e c2 [2] 3a da [2] 7d d8 [2] 3a c9 [2] 74 c5 [2] 78 cf [2] 6f c4 [2] 74 8a [2] 49 }

  condition:
    any of them
}