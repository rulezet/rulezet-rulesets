rule TTP_XOR_MULT_DOSStub_c0aa {
  strings:
    $key_c0aa = { 94 c2 [2] e0 da [2] a7 d8 [2] e0 c9 [2] ae c5 [2] a2 cf [2] b5 c4 [2] ae 8a [2] 93 }

  condition:
    any of them
}