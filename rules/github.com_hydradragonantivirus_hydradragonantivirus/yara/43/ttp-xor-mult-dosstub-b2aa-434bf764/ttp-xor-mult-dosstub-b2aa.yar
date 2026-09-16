rule TTP_XOR_MULT_DOSStub_b2aa {
  strings:
    $key_b2aa = { e6 c2 [2] 92 da [2] d5 d8 [2] 92 c9 [2] dc c5 [2] d0 cf [2] c7 c4 [2] dc 8a [2] e1 }

  condition:
    any of them
}