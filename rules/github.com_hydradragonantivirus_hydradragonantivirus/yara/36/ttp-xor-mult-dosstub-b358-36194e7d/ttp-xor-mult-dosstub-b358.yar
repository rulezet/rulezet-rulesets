rule TTP_XOR_MULT_DOSStub_b358 {
  strings:
    $key_b358 = { e7 30 [2] 93 28 [2] d4 2a [2] 93 3b [2] dd 37 [2] d1 3d [2] c6 36 [2] dd 78 [2] e0 }

  condition:
    any of them
}