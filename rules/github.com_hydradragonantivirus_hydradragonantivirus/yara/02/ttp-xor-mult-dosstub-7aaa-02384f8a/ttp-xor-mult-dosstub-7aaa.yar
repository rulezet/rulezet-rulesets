rule TTP_XOR_MULT_DOSStub_7aaa {
  strings:
    $key_7aaa = { 2e c2 [2] 5a da [2] 1d d8 [2] 5a c9 [2] 14 c5 [2] 18 cf [2] 0f c4 [2] 14 8a [2] 29 }

  condition:
    any of them
}