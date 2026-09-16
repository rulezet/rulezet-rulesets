rule TTP_XOR_MULT_DOSStub_f2aa {
  strings:
    $key_f2aa = { a6 c2 [2] d2 da [2] 95 d8 [2] d2 c9 [2] 9c c5 [2] 90 cf [2] 87 c4 [2] 9c 8a [2] a1 }

  condition:
    any of them
}