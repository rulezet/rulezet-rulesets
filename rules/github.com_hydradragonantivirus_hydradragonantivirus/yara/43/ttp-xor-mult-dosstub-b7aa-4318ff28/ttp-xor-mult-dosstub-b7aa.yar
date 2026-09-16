rule TTP_XOR_MULT_DOSStub_b7aa {
  strings:
    $key_b7aa = { e3 c2 [2] 97 da [2] d0 d8 [2] 97 c9 [2] d9 c5 [2] d5 cf [2] c2 c4 [2] d9 8a [2] e4 }

  condition:
    any of them
}