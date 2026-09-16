rule TTP_XOR_MULT_DOSStub_b5aa {
  strings:
    $key_b5aa = { e1 c2 [2] 95 da [2] d2 d8 [2] 95 c9 [2] db c5 [2] d7 cf [2] c0 c4 [2] db 8a [2] e6 }

  condition:
    any of them
}