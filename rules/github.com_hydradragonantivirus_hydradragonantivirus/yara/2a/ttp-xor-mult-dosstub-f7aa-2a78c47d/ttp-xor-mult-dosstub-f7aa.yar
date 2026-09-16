rule TTP_XOR_MULT_DOSStub_f7aa {
  strings:
    $key_f7aa = { a3 c2 [2] d7 da [2] 90 d8 [2] d7 c9 [2] 99 c5 [2] 95 cf [2] 82 c4 [2] 99 8a [2] a4 }

  condition:
    any of them
}