rule TTP_XOR_MULT_DOSStub_3aaa {
  strings:
    $key_3aaa = { 6e c2 [2] 1a da [2] 5d d8 [2] 1a c9 [2] 54 c5 [2] 58 cf [2] 4f c4 [2] 54 8a [2] 69 }

  condition:
    any of them
}